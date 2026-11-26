//! Which local agent and command sent a credential request, found by looking
//! for the `aac run` process that carries the same query.
//!
//! Display only: any local process can forge its name and argv, so nothing
//! here may feed the approve or deny decision. The touch on immurok decides.

use std::collections::HashMap;
use std::ffi::c_int;

use ap_client::CredentialQuery;
use tracing::{debug, info};
use zeroize::Zeroizing;

const AAC: &str = "aac";
const KNOWN_AGENTS: &[(&str, &str)] = &[
    ("claude", "Claude Code"),
    ("codex", "Codex"),
    ("gemini", "Gemini CLI"),
    ("opencode", "opencode"),
    ("aider", "Aider"),
    ("cursor-agent", "Cursor Agent"),
];
const NOT_AN_AGENT: &[&str] = &[
    "sh", "bash", "zsh", "fish", "dash", "tcsh", "login", "launchd",
];
// Scripts run under these show the interpreter as argv[0]; the script names the program.
const INTERPRETERS: &[&str] = &["node", "bun", "deno"];
const INLINE_CODE: &[&str] = &["-c", "-e", "--eval", "-p", "--print", "-m"];
const MAX_DEPTH: usize = 64;

pub enum Requester {
    Local {
        agent: Option<String>,
        command: Option<String>,
    },
    Remote,
    Ambiguous,
}

impl Requester {
    pub fn origin(&self) -> &'static str {
        match self {
            Self::Local { .. } => "local",
            Self::Remote => "remote",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// Runs off the async workers: it walks the whole process table.
pub async fn detect(query: &CredentialQuery) -> Requester {
    let query = query.clone();
    let requester = tokio::task::spawn_blocking(move || find(&query))
        .await
        .unwrap_or(Requester::Ambiguous);
    match &requester {
        Requester::Local { agent, command } => {
            info!(origin = requester.origin(), agent, "requester");
            // The command line may carry secrets, so it never reaches info logs.
            debug!(command, "requester command");
        }
        other => info!(origin = other.origin(), "requester"),
    }
    requester
}

fn find(query: &CredentialQuery) -> Requester {
    let (flag, value) = match query {
        CredentialQuery::Id(v) => ("--id", v.as_str()),
        CredentialQuery::Domain(v) => ("--domain", v.as_str()),
        // `aac run` cannot send a free-text search.
        CredentialQuery::Search(_) => return Requester::Remote,
    };
    let table: HashMap<i32, Proc> = processes().into_iter().map(|p| (p.pid, p)).collect();
    // The kernel name narrows the search first: only aac processes and, for a
    // single match, its ancestors are read, each buffer (environment included)
    // zeroed after argv is parsed out.
    let matches: Vec<(i32, Vec<String>)> = table
        .values()
        .filter(|p| p.name == AAC)
        .filter_map(|p| {
            let argv = argv(p.pid)?;
            is_request(&argv, flag, value).then_some((p.ppid, argv))
        })
        .collect();
    let [(ppid, aac_argv)] = matches.as_slice() else {
        return if matches.is_empty() {
            Requester::Remote
        } else {
            Requester::Ambiguous
        };
    };
    let agent = agent(*ppid, |pid| {
        let p = table.get(&pid)?;
        let argv = argv(pid).unwrap_or_default();
        Some(Ancestor {
            ppid: p.ppid,
            program: program(&argv, &p.name),
            name: p.name.clone(),
        })
    });
    Requester::Local {
        agent,
        command: command(aac_argv),
    }
}

/// `aac [opts] run ... <flag> <value> ...` or `<flag>=<value>`, looking only
/// before the `--` that starts the wrapped command.
fn is_request(argv: &[String], flag: &str, value: &str) -> bool {
    let Some((first, rest)) = argv.split_first() else {
        return false;
    };
    if basename(first) != AAC {
        return false;
    }
    let opts = rest.split(|a| a == "--").next().unwrap_or_default();
    // Global options such as --proxy-url <url> may come before the subcommand.
    let Some(run) = opts.iter().position(|a| a == "run") else {
        return false;
    };
    let opts = &opts[run + 1..];
    opts.iter().enumerate().any(|(i, a)| {
        a.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) == Some(value)
            || (a == flag && opts.get(i + 1).map(String::as_str) == Some(value))
    })
}

/// The wrapped command after `--`, quoted so arguments with spaces stay whole.
fn command(argv: &[String]) -> Option<String> {
    let dash = argv.iter().position(|a| a == "--")?;
    let words = &argv[dash + 1..];
    (!words.is_empty()).then(|| {
        words
            .iter()
            .map(|w| {
                if w.chars().any(char::is_whitespace) {
                    format!("'{}'", w.replace('\'', r"'\''"))
                } else {
                    w.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    })
}

struct Ancestor {
    ppid: i32,
    /// From argv: Claude Code's kernel name is its version number.
    program: String,
    /// The kernel's name for the executable.
    name: String,
}

/// The first known agent up the parent chain, else the first ancestor that is
/// not a shell, login or launchd.
fn agent(start: i32, lookup: impl Fn(i32) -> Option<Ancestor>) -> Option<String> {
    let mut chain = Vec::new();
    let mut pid = start;
    while pid > 0 && chain.len() < MAX_DEPTH {
        let Some(a) = lookup(pid) else { break };
        let next = a.ppid;
        chain.push(a);
        if next == pid {
            break;
        }
        pid = next;
    }
    let known = |n: &str| {
        KNOWN_AGENTS
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| v.to_string())
    };
    chain
        .iter()
        .find_map(|a| known(&a.program).or_else(|| known(&a.name)))
        .or_else(|| {
            chain
                .iter()
                .find(|a| !NOT_AN_AGENT.contains(&a.program.as_str()))
                .map(|a| a.program.clone())
        })
}

fn program(argv: &[String], name: &str) -> String {
    let base = |s: &str| basename(s).trim_start_matches('-').to_string();
    match argv {
        [first, rest @ ..]
            if INTERPRETERS.contains(&base(first).as_str())
                || base(first).starts_with("python") =>
        {
            // Inline code (-c, -e) is not a program name and may hold anything.
            rest.iter()
                .take_while(|a| !INLINE_CODE.contains(&a.as_str()))
                .find(|a| !a.starts_with('-'))
                .map_or_else(|| base(first), |script| base(script))
        }
        [first, ..] if !first.is_empty() => base(first),
        _ => name.to_string(),
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

struct Proc {
    pid: i32,
    ppid: i32,
    name: String,
}

fn processes() -> Vec<Proc> {
    // SAFETY: a null buffer only asks for the count.
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    // Room for processes started between the two calls.
    let mut pids = vec![0 as c_int; n as usize + 64];
    let bytes = (pids.len() * size_of::<c_int>()) as c_int;
    // SAFETY: the buffer holds exactly `bytes` bytes of c_int.
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    pids.truncate(n.max(0) as usize);
    pids.into_iter().filter_map(bsd_info).collect()
}

fn bsd_info(pid: c_int) -> Option<Proc> {
    // SAFETY: proc_bsdinfo is plain data; all zeroes is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = size_of::<libc::proc_bsdinfo>() as c_int;
    // SAFETY: the buffer is one proc_bsdinfo of `size` bytes.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if got != size {
        return None;
    }
    let text = |raw: &[libc::c_char]| {
        let bytes: Vec<u8> = raw
            .iter()
            .map(|&c| c as u8)
            .take_while(|&b| b != 0)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let name = Some(text(&info.pbi_name))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| text(&info.pbi_comm));
    Some(Proc {
        pid,
        ppid: info.pbi_ppid as i32,
        name,
    })
}

/// KERN_PROCARGS2 also returns the process's environment after argv; the
/// buffer is zeroed on drop and only argv is parsed out of it.
fn argv(pid: c_int) -> Option<Vec<String>> {
    // A buffer smaller than the args area gets its tail, where environment
    // strings would parse as argv; ARGMAX bytes always hold the whole area,
    // even if the process re-execs between calls.
    let mut size = arg_max()?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut buf = Zeroizing::new(vec![0u8; size]);
    // SAFETY: the buffer holds `size` bytes, and sysctl writes at most that.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    parse_procargs(&buf[..size.min(buf.len())])
}

fn arg_max() -> Option<usize> {
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let mut value: c_int = 0;
    let mut size = size_of::<c_int>();
    // SAFETY: the buffer is one c_int of `size` bytes.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut value as *mut c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0).then_some(())?;
    usize::try_from(value).ok().filter(|&v| v > 0)
}

/// Layout: argc (native int), exec path, NUL padding, argc strings, then the
/// environment, which this never reads.
fn parse_procargs(buf: &[u8]) -> Option<Vec<String>> {
    let argc = c_int::from_ne_bytes(buf.get(..size_of::<c_int>())?.try_into().ok()?);
    let argc = usize::try_from(argc).ok()?;
    let strings = &buf[size_of::<c_int>()..];
    let path_end = strings.iter().position(|&b| b == 0)?;
    // The exec path is NUL-padded to an 8-byte boundary (measured on macOS
    // 27). Skipping every NUL instead would swallow an empty argv[0] and
    // return an environment string as the last argument.
    let argv_start = (path_end + 1).next_multiple_of(8);
    if strings.get(path_end..argv_start)?.iter().any(|&b| b != 0) {
        return None;
    }
    let mut rest = &strings[argv_start..];
    let mut out = Vec::with_capacity(argc.min(256));
    for _ in 0..argc {
        let end = rest.iter().position(|&b| b == 0)?;
        out.push(String::from_utf8_lossy(&rest[..end]).into_owned());
        rest = &rest[end + 1..];
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn matches_aac_run_with_the_same_id_or_domain() {
        let id = |a: &[&str]| is_request(&args(a), "--id", "GitHub:token");
        assert!(id(&["aac", "run", "--id", "GitHub:token", "--", "gh"]));
        assert!(id(&[
            "/Users/x/.local/bin/aac",
            "run",
            "--env-all",
            "--id=GitHub:token",
            "--",
            "gh"
        ]));
        assert!(!id(&["aac", "run", "--id", "GitHub:other", "--", "gh"]));
        assert!(!id(&["aac", "run", "--domain", "GitHub:token", "--", "gh"]));
        assert!(!id(&["aac", "run", "--", "echo", "--id", "GitHub:token"]));
        assert!(!id(&["aac", "connect", "--id", "GitHub:token"]));
        assert!(!id(&["aac", "--id", "GitHub:token"]));
        assert!(id(&[
            "aac",
            "--proxy-url",
            "wss://x",
            "run",
            "--id",
            "GitHub:token",
            "--",
            "gh"
        ]));
        assert!(!id(&["notaac", "run", "--id", "GitHub:token"]));
        assert!(!id(&["/bin/sh", "aac", "run", "--id", "GitHub:token"]));
        assert!(!id(&[]));
        let domain = |a: &[&str]| is_request(&args(a), "--domain", "example.com");
        assert!(domain(&[
            "aac",
            "run",
            "--domain",
            "example.com",
            "--",
            "psql"
        ]));
        assert!(domain(&[
            "aac",
            "run",
            "--domain=example.com",
            "--",
            "psql"
        ]));
        assert!(!domain(&[
            "aac",
            "run",
            "--id",
            "example.com",
            "--",
            "psql"
        ]));
    }

    #[test]
    fn command_is_what_follows_the_double_dash_quoted() {
        let c = |a: &[&str]| command(&args(a));
        assert_eq!(
            c(&["aac", "run", "--id", "x", "--", "gh", "api", "/user"]).as_deref(),
            Some("gh api /user")
        );
        assert_eq!(
            c(&[
                "aac",
                "run",
                "--id",
                "x",
                "--",
                "sh",
                "-c",
                "echo it's here"
            ])
            .as_deref(),
            Some(r"sh -c 'echo it'\''s here'")
        );
        assert_eq!(
            c(&["aac", "run", "--id", "x", "--", "a", "--", "b"]).as_deref(),
            Some("a -- b")
        );
        assert_eq!(c(&["aac", "run", "--id", "x", "--"]), None);
        assert_eq!(c(&["aac", "run", "--id", "x", "gh"]), None);
    }

    fn walk(table: &[(i32, i32, &str, &[&str])], start: i32) -> Option<String> {
        agent(start, |pid| {
            let (_, ppid, name, argv) = table.iter().find(|(p, ..)| *p == pid)?;
            Some(Ancestor {
                ppid: *ppid,
                program: program(&args(argv), name),
                name: name.to_string(),
            })
        })
    }

    #[test]
    fn agent_is_the_first_known_ancestor() {
        // Claude Code's kernel name is its version; argv[0] says claude.
        let table: &[(i32, i32, &str, &[&str])] = &[
            (30, 20, "bash", &["/bin/bash", "-c", "aac run"]),
            (20, 10, "2.1.332", &["claude"]),
            (10, 1, "rex", &["/Applications/Rex.app/Contents/MacOS/rex"]),
            (1, 0, "launchd", &["/sbin/launchd"]),
        ];
        assert_eq!(walk(table, 30).as_deref(), Some("Claude Code"));
        let table: &[(i32, i32, &str, &[&str])] = &[
            (30, 20, "zsh", &["-zsh"]),
            (
                20,
                10,
                "node",
                &["node", "--no-warnings", "/opt/homebrew/bin/gemini"],
            ),
            (10, 1, "login", &["login", "-pf", "me"]),
        ];
        assert_eq!(walk(table, 30).as_deref(), Some("Gemini CLI"));
    }

    #[test]
    fn agent_falls_back_to_the_first_non_shell_then_unknown() {
        let table: &[(i32, i32, &str, &[&str])] = &[
            (30, 20, "fish", &["-fish"]),
            (20, 10, "login", &["login"]),
            (
                10,
                1,
                "Terminal",
                &["/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"],
            ),
            (1, 0, "launchd", &["/sbin/launchd"]),
        ];
        assert_eq!(walk(table, 30).as_deref(), Some("Terminal"));
        let table: &[(i32, i32, &str, &[&str])] = &[
            (30, 20, "sh", &["sh"]),
            (20, 1, "login", &[]),
            (1, 1, "launchd", &[]),
        ];
        assert_eq!(walk(table, 30), None);
        assert_eq!(walk(&[], 30), None);
    }

    #[test]
    fn inline_interpreter_code_never_becomes_the_name() {
        let p = |a: &[&str]| program(&args(a), "python3");
        assert_eq!(p(&["python3", "-c", "import os; print(1)"]), "python3");
        assert_eq!(p(&["node", "-e", "require('x')"]), "node");
        assert_eq!(p(&["python3", "-m", "aider"]), "python3");
        assert_eq!(p(&["python3", "-u", "/Users/me/.local/bin/aider"]), "aider");
    }

    /// argc, the exec path NUL-padded to 8 bytes as the kernel does, then strings.
    fn procargs(argc: i32, strings: &[&str]) -> Vec<u8> {
        let mut buf = argc.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/usr/local/bin/aac\0\0\0\0\0\0");
        for s in strings {
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
        }
        buf
    }

    #[test]
    fn procargs_parser_stops_at_argc_and_never_returns_the_environment() {
        let buf = procargs(
            3,
            &["aac", "run", "--id=x", "SECRET=hunter2", "HOME=/Users/me"],
        );
        let argv = parse_procargs(&buf).unwrap();
        assert_eq!(argv, ["aac", "run", "--id=x"]);
        assert!(
            argv.iter()
                .all(|a| !a.contains("SECRET") && !a.contains("HOME"))
        );
        assert_eq!(
            parse_procargs(&procargs(0, &["ENV=1"])).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(parse_procargs(&procargs(4, &["a", "b"])), None);
        assert_eq!(parse_procargs(&procargs(-1, &["a"])), None);
        assert_eq!(parse_procargs(&[1, 0]), None);
    }

    #[test]
    fn empty_argv0_is_kept_and_the_environment_still_excluded() {
        let buf = procargs(4, &["", "run", "--id", "x", "PROBE_TOKEN=hunter2"]);
        assert_eq!(parse_procargs(&buf).unwrap(), ["", "run", "--id", "x"]);
        let mut short_pad = 2i32.to_ne_bytes().to_vec();
        short_pad.extend_from_slice(b"/usr/local/bin/aac\0a\0b\0ENV=1\0");
        assert_eq!(parse_procargs(&short_pad), None);
    }

    #[test]
    fn finds_a_real_child_through_libproc() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("31.4159")
            .env("IMK_AAC_TEST_SECRET", "s3cret")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let mut seen = None;
        for _ in 0..50 {
            let listed = processes().into_iter().find(|p| p.pid == pid);
            let argv = argv(pid);
            if argv
                .as_ref()
                .is_some_and(|a| a.first().map(String::as_str) == Some("/bin/sleep"))
            {
                seen = listed.zip(argv);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
        let (p, argv) = seen.expect("child listed with its argv");
        assert_eq!(p.ppid, std::process::id() as i32);
        assert_eq!(p.name, "sleep");
        assert_eq!(argv, ["/bin/sleep", "31.4159"]);
    }
}
