//! immurok's overlay shows the gated command line, so imk runs `Bitwarden
//! <text>` from a private PATH where `Bitwarden` is a link to /usr/bin/true,
//! and the overlay reads as a sentence instead of a path.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use tokio::process::Command;
use tracing::warn;

const SHOWN: &str = "Bitwarden";
const TRUE: &str = "/usr/bin/true";
const DIR: &str = "Library/Application Support/imk-aac/bin";
// Its own dir, as this link must also be named `Bitwarden`.
const SELF_DIR: &str = "Library/Application Support/imk-aac/self";

/// `imk run --agent` gating a no-op whose command line is `Bitwarden <text>`,
/// or `/usr/bin/true <text>` when the private PATH cannot be trusted.
pub fn imk_run(imk: &str, text: &str) -> Command {
    let mut cmd = Command::new(imk);
    match ready(DIR, Path::new(TRUE)) {
        Ok(dir) => {
            cmd.env("PATH", dir)
                .args(["run", "--agent", "--", SHOWN, text]);
        }
        Err(e) => {
            warn!("private PATH unusable ({e}); overlay shows {TRUE}");
            cmd.args(["run", "--agent", "--", TRUE, text]);
        }
    }
    cmd
}

/// `imk run --agent` gating this binary as `Bitwarden <text>`, for a command
/// that must itself be imk's child; [`gated_self`] then tells the gated copy
/// apart. `fallback` is gated instead when the private PATH cannot be trusted.
pub fn imk_run_self(imk: &str, text: &str, fallback: &[&str]) -> Command {
    let mut cmd = Command::new(imk);
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| format!("cannot locate this binary: {e}"));
    match exe.and_then(|exe| ready(SELF_DIR, &exe)) {
        Ok(dir) => {
            cmd.env("PATH", dir)
                .args(["run", "--agent", "--", SHOWN, text]);
        }
        Err(e) => {
            warn!(
                "private PATH unusable ({e}); overlay shows {}",
                fallback.join(" ")
            );
            cmd.args(["run", "--agent", "--"]).args(fallback);
        }
    }
    cmd
}

/// Whether this process is the copy [`imk_run_self`] gated with `text`. Only
/// the argument is compared: how imk spells argv[0] is not ours to rely on.
pub fn gated_self(text: &str) -> bool {
    is_gated(std::env::args_os(), text)
}

fn is_gated(args: impl IntoIterator<Item = OsString>, text: &str) -> bool {
    let mut rest = args.into_iter().skip(1);
    rest.next().as_deref() == Some(OsStr::new(text)) && rest.next().is_none()
}

fn ready(sub: &str, target: &Path) -> Result<PathBuf, String> {
    let dir = dirs::home_dir().ok_or("no home directory")?.join(sub);
    prepare(&dir, target).map_err(|e| format!("cannot set up {}: {e}", dir.display()))?;
    // SAFETY: getuid has no preconditions and cannot fail.
    verify(&dir, unsafe { libc::getuid() }, target)?;
    Ok(dir)
}

/// Creates what is missing and never repairs what exists: anything wrong is
/// left for verify to refuse.
fn prepare(dir: &Path, target: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let link = dir.join(SHOWN);
    match fs::symlink_metadata(&link) {
        Err(e) if e.kind() == ErrorKind::NotFound => std::os::unix::fs::symlink(target, &link),
        other => other.map(|_| ()),
    }
}

/// Checked before every use: imk resolves `Bitwarden` through this PATH, so
/// only this user may be able to change what it points at.
fn verify(dir: &Path, uid: u32, target: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if meta.uid() != uid {
        return Err(format!("{} is owned by uid {}", dir.display(), meta.uid()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!("{} is writable by group or others", dir.display()));
    }
    let link = dir.join(SHOWN);
    let meta = fs::symlink_metadata(&link).map_err(|e| e.to_string())?;
    if !meta.file_type().is_symlink() {
        return Err(format!("{} is not a symlink", link.display()));
    }
    let found = fs::read_link(&link).map_err(|e| e.to_string())?;
    if found != target {
        return Err(format!("{} points at {}", link.display(), found.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("imk-aac-overlay-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn true_() -> &'static Path {
        Path::new(TRUE)
    }

    fn uid() -> u32 {
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { libc::getuid() }
    }

    #[test]
    fn prepared_dir_passes() {
        let dir = scratch("good");
        prepare(&dir, true_()).unwrap();
        assert_eq!(fs::symlink_metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(verify(&dir, uid(), true_()), Ok(()));
        prepare(&dir, true_()).unwrap();
        assert_eq!(verify(&dir, uid(), true_()), Ok(()));
        assert!(verify(&dir, uid() + 1, true_()).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn link_to_another_target_fails() {
        let dir = scratch("target");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .unwrap();
        std::os::unix::fs::symlink("/bin/sh", dir.join(SHOWN)).unwrap();
        prepare(&dir, true_()).unwrap();
        assert!(
            verify(&dir, uid(), true_())
                .unwrap_err()
                .contains("points at /bin/sh")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn regular_file_fails() {
        let dir = scratch("file");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .unwrap();
        fs::write(dir.join(SHOWN), "#!/bin/sh\n").unwrap();
        prepare(&dir, true_()).unwrap();
        assert!(
            verify(&dir, uid(), true_())
                .unwrap_err()
                .contains("not a symlink")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn group_writable_dir_fails() {
        let dir = scratch("perm");
        prepare(&dir, true_()).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(
            verify(&dir, uid(), true_())
                .unwrap_err()
                .contains("writable")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn self_link_must_point_at_the_given_binary() {
        let dir = scratch("self");
        let exe = Path::new("/usr/local/bin/imk-aac");
        prepare(&dir, exe).unwrap();
        assert_eq!(verify(&dir, uid(), exe), Ok(()));
        assert!(
            verify(&dir, uid(), Path::new("/elsewhere/imk-aac"))
                .unwrap_err()
                .contains("points at /usr/local/bin/imk-aac")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_the_exact_text_marks_the_gated_copy() {
        let args = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(is_gated(args(&["Bitwarden", "unlock"]), "unlock"));
        assert!(is_gated(args(&["/x/self/Bitwarden", "unlock"]), "unlock"));
        assert!(!is_gated(args(&["imk-aac"]), "unlock"));
        assert!(!is_gated(args(&["Bitwarden", "unlock", "x"]), "unlock"));
        assert!(!is_gated(args(&["Bitwarden", "unlock "]), "unlock"));
    }
}
