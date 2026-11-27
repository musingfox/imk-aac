use std::process::Stdio;
use std::time::Duration;

use ap_client::{CredentialData, CredentialQuery};
use serde::Deserialize;
use tokio::process::{Child, Command};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::overlay;
use crate::panel::{self, Outcome, Panel};
use crate::picker::Picker;

// Absolute paths: a planted bw or imk earlier on PATH would otherwise receive
// the master password or the session.
const BW: &str = "/opt/homebrew/bin/bw";
const IMK: &str = "/usr/local/bin/imk";
const MASTER_KEY_URL: &str = "imk://api/bitwarden";
// Under launchd a bare `imk get` shows no overlay (immurok treats the caller as
// manual), so it runs inside `imk run --agent`, whose overlay launchd callers do
// get; the nested get then needs no second touch (measured with immurok 1.6.11).
// At boot immurok's BLE link may not be up yet, so a failed attempt is retried.
const UNLOCK_ATTEMPTS: u32 = 5;
const UNLOCK_RETRY_DELAY: Duration = Duration::from_secs(10);
/// What the overlay reads after `Bitwarden` while the boot unlock waits, and
/// the argument by which the gated copy of this binary knows its job.
pub const UNLOCK_TEXT: &str = "解鎖密碼庫";
// The measured get ran with launchd's default PATH, not the overlay's private one.
const LAUNCHD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

// immurok's overlay shows about two lines of the gated command and cuts the
// rest (measured with immurok 1.6.11), so the summary is kept short.
const SUMMARY_MAX_CHARS: usize = 60;

/// `--id <item>:?` asks for the item's custom field names, never their values,
/// so an agent can learn what to ask for next.
const LIST_FIELDS: &str = "?";
const LIST_FIELDS_LABEL: &str = "欄位名稱清單";

/// `--id <item>:~<need>` lets the optional local model pick the field; the
/// overlay marks the pick so the user knows a model chose it.
const PICK_PREFIX: char = '~';
const PICKED_MARK: &str = "（自動選擇）";

/// A credential and what the approval overlay and panel show for it.
pub struct Found {
    pub credential: CredentialData,
    pub item: String,
    pub field: String,
    pub picked: bool,
}

impl Found {
    fn new(
        credential: CredentialData,
        item: Option<&str>,
        field: Option<&str>,
        picked: bool,
    ) -> Self {
        let clean = |s: &str| s.chars().filter(|c| !c.is_control()).collect::<String>();
        Self {
            credential,
            item: clean(item.unwrap_or("?")),
            field: clean(field.unwrap_or("login")),
            picked,
        }
    }

    pub fn summary(&self) -> String {
        summary(&self.item, &self.field, self.picked)
    }
}

pub struct Vault {
    session: Zeroizing<String>,
    picker: Option<Picker>,
    // A field only so tests can point at a stub; production always uses BW.
    bw: &'static str,
}

impl Vault {
    pub async fn unlock(picker: Option<Picker>) -> Result<Self, UnlockError> {
        let master = master_password().await?;
        let out = Command::new(BW)
            .args([
                "unlock",
                "--nointeraction",
                "--passwordenv",
                "BW_MASTER_PASSWORD",
                "--raw",
            ])
            .env("BW_MASTER_PASSWORD", master.as_str())
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| format!("cannot run {BW}: {e}"))?;
        drop(master);
        let session = Zeroizing::new(String::from_utf8_lossy(&out.stdout).trim().to_string());
        if !out.status.success() || session.is_empty() {
            return Err(format!(
                "bw unlock failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )
            .into());
        }
        Ok(Self {
            session,
            picker,
            bw: BW,
        })
    }

    pub async fn sync(&self) -> Result<(), String> {
        let out = self.bw(&["sync"]).await?;
        if out.status.success() {
            info!("bw sync done");
            Ok(())
        } else {
            Err(format!(
                "bw sync failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    /// Syncs at startup without making a failure fatal: exiting would make
    /// launchd restart the daemon, and every restart asks for the fingerprint
    /// again. After unlock `bw` serves from its local cache, and a lookup miss
    /// syncs again anyway.
    pub async fn boot_sync(&self) -> bool {
        match self.sync().await {
            Ok(()) => true,
            Err(e) => {
                warn!("boot sync failed, continuing with the local cache: {e}");
                false
            }
        }
    }

    /// Looks the item up, and on a miss syncs once and looks again, so items
    /// added on other devices are found without restarting.
    pub async fn lookup(&self, query: &CredentialQuery) -> Result<Option<Found>, String> {
        let (search, field) = target(query);
        if field.is_some_and(|f| f.starts_with(PICK_PREFIX)) && self.picker.is_none() {
            warn!(search, "field picking is off; see the startup log for why");
            return Ok(None);
        }
        if let Some(c) = self.get(search, field).await? {
            return Ok(Some(c));
        }
        info!(search, field, "not found; syncing and retrying");
        self.sync().await?;
        self.get(search, field).await
    }

    async fn get(&self, search: &str, field: Option<&str>) -> Result<Option<Found>, String> {
        let out = self.bw(&["get", "item", search]).await?;
        if out.status.success() {
            let (credential, shown, picked) = match field {
                Some(LIST_FIELDS) => (
                    names_from_item(&out.stdout),
                    Some(LIST_FIELDS_LABEL.to_string()),
                    false,
                ),
                Some(f) if f.starts_with(PICK_PREFIX) => {
                    match self
                        .pick_field(&out.stdout, &f[PICK_PREFIX.len_utf8()..])
                        .await
                    {
                        Some(name) => (field_from_item(&out.stdout, &name), Some(name), true),
                        None => (None, None, false),
                    }
                }
                Some(name) => {
                    let found = field_from_item(&out.stdout, name);
                    if found.is_none() {
                        info!(search, field = name, present = ?field_names(&out.stdout), "item has no such field");
                    }
                    (found, Some(name.to_string()), false)
                }
                None => (credential_from_item(&out.stdout), None, false),
            };
            let item = item_name(&out.stdout);
            return Ok(credential.map(|credential| {
                Found::new(credential, item.as_deref(), shown.as_deref(), picked)
            }));
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("Not found") {
            Ok(None)
        } else {
            Err(format!("bw get item failed: {}", stderr.trim()))
        }
    }

    async fn pick_field(&self, item: &[u8], need: &str) -> Option<String> {
        let picker = self.picker.as_ref()?;
        let names = named_fields(item);
        if names.is_empty() || need.trim().is_empty() {
            return None;
        }
        picker.pick(&names, need.trim()).await
    }

    async fn bw(&self, args: &[&str]) -> Result<std::process::Output, String> {
        Command::new(self.bw)
            .args(args)
            .env("BW_SESSION", self.session.as_str())
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| format!("cannot run {}: {e}", self.bw))
    }
}

/// The gated copy of this binary replaces itself with imk get, so the get stays
/// imk run's own child, as measured, and its stdout goes straight to the pipe.
pub fn exec_master_key_get() -> std::io::Error {
    use std::os::unix::process::CommandExt;
    std::process::Command::new(IMK)
        .args(["get", MASTER_KEY_URL])
        .env("PATH", LAUNCHD_PATH)
        .exec()
}

enum Attempt {
    Released(Zeroizing<String>),
    Failed,
    Denied,
}

/// Why the boot unlock stopped. A denial is a deliberate no, so the caller
/// must tell it apart from a failure without parsing the message.
#[derive(Debug, PartialEq, Eq)]
pub enum UnlockError {
    Denied,
    Failed(String),
}

impl std::fmt::Display for UnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied => f.write_str("Bitwarden unlock denied in the approval panel"),
            Self::Failed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for UnlockError {}

impl From<String> for UnlockError {
    fn from(why: String) -> Self {
        Self::Failed(why)
    }
}

async fn master_password() -> Result<Zeroizing<String>, UnlockError> {
    for attempt in 1..=UNLOCK_ATTEMPTS {
        info!(attempt, "touch immurok to unlock Bitwarden");
        let imk = overlay::imk_run_self(IMK, UNLOCK_TEXT, &[IMK, "get", MASTER_KEY_URL])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("cannot run {IMK}: {e}"))?;
        let panel = Panel::show(&unlock_request()).await;
        match released(imk, panel, attempt).await {
            Attempt::Released(master) => return Ok(master),
            // Retries are for a BLE link not yet up, not for overriding a no.
            Attempt::Denied => return Err(UnlockError::Denied),
            Attempt::Failed => {}
        }
        if attempt < UNLOCK_ATTEMPTS {
            tokio::time::sleep(UNLOCK_RETRY_DELAY).await;
        }
    }
    Err(format!("immurok did not release {MASTER_KEY_URL} after {UNLOCK_ATTEMPTS} attempts").into())
}

fn unlock_request() -> panel::Request<'static> {
    panel::Request {
        provider: crate::PROVIDER,
        item: MASTER_KEY_URL,
        field: "",
        picked: false,
        origin: "local",
        agent: None,
        command: None,
        query: MASTER_KEY_URL,
        timeout_secs: crate::TOUCH_TIMEOUT_SECS,
        unlock: true,
    }
}

/// Only imk's own success releases the password; the panel can end the
/// attempt, never approve it.
async fn released(imk: Child, mut panel: Option<Panel>, attempt: u32) -> Attempt {
    // Returning drops this wait, and kill_on_drop then kills imk.
    let output = imk.wait_with_output();
    tokio::pin!(output);
    loop {
        tokio::select! {
            out = &mut output => {
                if let Some(p) = panel.take() {
                    p.close().await;
                }
                let out = match out {
                    Ok(out) => out,
                    Err(e) => {
                        warn!(attempt, "cannot wait for {IMK}: {e}");
                        return Attempt::Failed;
                    }
                };
                let master = Zeroizing::new(
                    String::from_utf8_lossy(&out.stdout)
                        .trim_end_matches('\n')
                        .to_string(),
                );
                if out.status.success() && !master.is_empty() {
                    return Attempt::Released(master);
                }
                warn!(attempt, code = ?out.status.code(), "unlock attempt failed: {}", String::from_utf8_lossy(&out.stderr).trim());
                return Attempt::Failed;
            }
            outcome = panel::outcome(&mut panel) => match outcome {
                Outcome::Denied => {
                    warn!(attempt, "unlock denied by user");
                    return Attempt::Denied;
                }
                Outcome::TimedOut => {
                    warn!(attempt, "unlock timed out");
                    return Attempt::Failed;
                }
                Outcome::Failed(code) => {
                    warn!(attempt, ?code, "approval panel failed; touch gate alone");
                    panel = None;
                }
            },
        }
    }
}

/// `--id <item>:<field>` asks for one custom field. The protocol has no custom
/// field slot (upstream issue #160), so the value travels as the password.
/// Only Id queries are split: a Domain like `host:8080` keeps its colon.
fn target(query: &CredentialQuery) -> (&str, Option<&str>) {
    match query {
        CredentialQuery::Id(id) => match id.split_once(':') {
            Some((item, field)) if !item.is_empty() && !field.is_empty() => (item, Some(field)),
            _ => (id, None),
        },
        other => (other.search_string(), None),
    }
}

#[derive(Deserialize)]
struct BwItem {
    id: Option<String>,
    name: Option<String>,
    login: Option<BwLogin>,
    #[serde(default)]
    fields: Vec<BwField>,
}

#[derive(Deserialize)]
struct BwField {
    name: Option<String>,
    value: Option<String>,
}

#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwUri>>,
}

#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

// Same mapping as upstream ap-cli's Bitwarden provider: only the login block.
fn credential_from_item(json: &[u8]) -> Option<CredentialData> {
    let item: BwItem = serde_json::from_slice(json).ok()?;
    let login = item.login?;
    let uri = login
        .uris
        .as_ref()
        .and_then(|u| u.first())
        .and_then(|u| u.uri.clone());
    let domain = uri.as_deref().and_then(domain_from_uri);
    Some(CredentialData {
        username: login.username,
        password: login.password.map(Zeroizing::new),
        totp: login.totp,
        uri,
        notes: None,
        credential_id: item.id,
        domain,
    })
}

fn field_from_item(json: &[u8], name: &str) -> Option<CredentialData> {
    let item: BwItem = serde_json::from_slice(json).ok()?;
    let value = item
        .fields
        .into_iter()
        .find(|f| f.name.as_deref() == Some(name))?
        .value?;
    Some(CredentialData {
        username: None,
        password: Some(Zeroizing::new(value)),
        totp: None,
        uri: None,
        notes: None,
        credential_id: item.id,
        domain: None,
    })
}

fn names_from_item(json: &[u8]) -> Option<CredentialData> {
    let names = named_fields(json);
    (!names.is_empty()).then(|| CredentialData {
        username: None,
        password: Some(Zeroizing::new(names.join(", "))),
        totp: None,
        uri: None,
        notes: None,
        credential_id: None,
        domain: None,
    })
}

fn named_fields(json: &[u8]) -> Vec<String> {
    field_names(json)
        .into_iter()
        .filter(|n| !n.is_empty())
        .collect()
}

fn item_name(json: &[u8]) -> Option<String> {
    serde_json::from_slice::<BwItem>(json).ok()?.name
}

/// "<item name> › <field>", the field marked when a model picked it. The item
/// name is cut first so the field always stays visible.
fn summary(item: &str, field: &str, picked: bool) -> String {
    let field = if picked {
        format!("{field}{PICKED_MARK}")
    } else {
        field.to_string()
    };
    let room = SUMMARY_MAX_CHARS
        .saturating_sub(field.chars().count() + 3)
        .max(8);
    let item = if item.chars().count() > room {
        item.chars().take(room - 1).chain(['…']).collect()
    } else {
        item.to_string()
    };
    format!("{item} › {field}")
}

fn field_names(json: &[u8]) -> Vec<String> {
    serde_json::from_slice::<BwItem>(json)
        .map(|item| item.fields.into_iter().filter_map(|f| f.name).collect())
        .unwrap_or_default()
}

fn domain_from_uri(uri: &str) -> Option<String> {
    let rest = uri.split_once("://").map_or(uri, |(_, r)| r);
    let rest = rest.split_once('@').map_or(rest, |(_, r)| r);
    let host = rest.split(['/', ':']).next()?;
    (!host.is_empty()).then(|| host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_item_maps_to_credential() {
        let json = br#"{"id":"abc","login":{"username":"u","password":"p","totp":null,"uris":[{"uri":"https://example.com:8443/x"}]}}"#;
        let c = credential_from_item(json).expect("login item");
        assert_eq!(c.username.as_deref(), Some("u"));
        assert_eq!(c.password.as_deref().map(String::as_str), Some("p"));
        assert_eq!(c.credential_id.as_deref(), Some("abc"));
        assert_eq!(c.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn item_without_login_is_not_a_credential() {
        assert!(credential_from_item(br#"{"id":"abc","type":2}"#).is_none());
    }

    const ITEM_WITH_FIELDS: &[u8] =
        br#"{"id":"abc","type":2,"fields":[{"name":"token","value":"t0k","type":1},{"name":"empty","value":null,"type":0}]}"#;

    #[test]
    fn named_field_becomes_the_password() {
        let c = field_from_item(ITEM_WITH_FIELDS, "token").expect("field");
        assert_eq!(c.password.as_deref().map(String::as_str), Some("t0k"));
        assert_eq!(c.credential_id.as_deref(), Some("abc"));
        assert!(c.username.is_none());
    }

    #[test]
    fn missing_or_valueless_field_is_not_found() {
        assert!(field_from_item(ITEM_WITH_FIELDS, "nope").is_none());
        assert!(field_from_item(ITEM_WITH_FIELDS, "empty").is_none());
        assert!(field_from_item(br#"{"id":"abc"}"#, "token").is_none());
    }

    #[test]
    fn field_listing_carries_names_and_no_values() {
        let c = names_from_item(ITEM_WITH_FIELDS).expect("names");
        let listed = c.password.as_deref().map(String::as_str);
        assert_eq!(listed, Some("token, empty"));
        assert!(!listed.unwrap().contains("t0k"));
        assert!(c.username.is_none() && c.uri.is_none() && c.notes.is_none());
        assert!(c.totp.is_none() && c.domain.is_none() && c.credential_id.is_none());
        assert!(names_from_item(br#"{"id":"abc","fields":[]}"#).is_none());
        assert!(names_from_item(br#"{"id":"abc"}"#).is_none());
        assert!(names_from_item(br#"{"id":"abc","fields":[{"name":"","value":"v"}]}"#).is_none());
    }

    fn found(item: Option<&str>, field: Option<&str>, picked: bool) -> Found {
        let credential = CredentialData {
            username: None,
            password: None,
            totp: None,
            uri: None,
            notes: None,
            credential_id: None,
            domain: None,
        };
        Found::new(credential, item, field, picked)
    }

    #[test]
    fn summary_names_item_and_field() {
        assert_eq!(
            found(Some("GitHub"), Some("token"), false).summary(),
            "GitHub › token"
        );
        assert_eq!(
            found(Some("GitHub"), None, false).summary(),
            "GitHub › login"
        );
        assert_eq!(found(None, None, false).summary(), "? › login");
        assert_eq!(
            found(Some("GitHub"), Some(LIST_FIELDS_LABEL), false).summary(),
            format!("GitHub › {LIST_FIELDS_LABEL}")
        );
    }

    #[test]
    fn picked_field_is_marked_in_the_summary_only() {
        let f = found(Some("Cloudflare"), Some("api-token"), true);
        assert_eq!(f.summary(), format!("Cloudflare › api-token{PICKED_MARK}"));
        assert_eq!(f.field, "api-token");
        assert!(f.picked);
    }

    #[test]
    fn summary_cuts_the_item_name_first_and_drops_control_chars() {
        let f = found(Some(&"n".repeat(100)), Some("api\ntoken"), false);
        assert_eq!(f.field, "apitoken");
        let s = f.summary();
        assert!(s.ends_with(" › apitoken"), "{s}");
        assert!(s.chars().count() <= SUMMARY_MAX_CHARS, "{s}");
        assert!(s.contains('…'));
    }

    #[test]
    fn only_id_queries_carry_a_field() {
        let id = |s: &str| CredentialQuery::Id(s.to_string());
        assert_eq!(target(&id("abc:token")), ("abc", Some("token")));
        assert_eq!(target(&id("abc:a:b")), ("abc", Some("a:b")));
        assert_eq!(target(&id("abc")), ("abc", None));
        assert_eq!(target(&id("abc:")), ("abc:", None));
        assert_eq!(target(&id(":token")), (":token", None));
        let domain = CredentialQuery::Domain("host:8080".to_string());
        assert_eq!(target(&domain), ("host:8080", None));
    }

    // Leaked so the stub path has the 'static lifetime Vault::bw wants.
    fn stub_vault(name: &str, script: &str) -> Vault {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("imk-aac-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bw");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Vault {
            session: Zeroizing::new("s".to_string()),
            picker: None,
            bw: Box::leak(path.to_string_lossy().into_owned().into_boxed_str()),
        }
    }

    const SYNC_TIMEOUT_STUB: &str = r#"
if [ "$1" = sync ]; then echo "connect ETIMEDOUT" >&2; exit 1; fi
if [ "$2" = item ] && [ "$3" = present ]; then
  echo '{"id":"i","name":"present","login":{"password":"p"}}'; exit 0
fi
echo "Not found." >&2; exit 1"#;

    #[tokio::test]
    async fn failed_boot_sync_is_not_an_error() {
        let vault = stub_vault("boot", SYNC_TIMEOUT_STUB);
        assert!(!vault.boot_sync().await);
        let ok = stub_vault("boot-ok", "exit 0");
        assert!(ok.boot_sync().await);
    }

    #[tokio::test]
    async fn lookup_with_failed_sync_errs_and_the_vault_keeps_serving() {
        let vault = stub_vault("lookup", SYNC_TIMEOUT_STUB);
        let id = |s: &str| CredentialQuery::Id(s.to_string());
        let err = vault.lookup(&id("missing")).await.err().expect("denied");
        assert!(err.contains("bw sync failed"), "{err}");
        let hit = vault.lookup(&id("present")).await.unwrap();
        assert!(hit.is_some());
    }

    fn sh(script: &str) -> Child {
        Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }

    fn panel_exiting(code: i32) -> Option<Panel> {
        Some(Panel::stub(sh(&format!("exit {code}"))))
    }

    #[tokio::test]
    async fn only_imk_success_with_output_releases() {
        match released(sh("printf 'pw\\n'"), None, 1).await {
            Attempt::Released(m) => assert_eq!(m.as_str(), "pw"),
            _ => panic!("not released"),
        }
        assert!(matches!(
            released(sh("printf pw; exit 1"), None, 1).await,
            Attempt::Failed
        ));
        assert!(matches!(
            released(sh("exit 0"), None, 1).await,
            Attempt::Failed
        ));
    }

    #[test]
    fn denial_is_distinct_from_other_unlock_errors() {
        let failed = UnlockError::from("bw unlock failed: x".to_string());
        assert_ne!(UnlockError::Denied, failed);
        assert!(matches!(failed, UnlockError::Failed(_)));
        // Even a failure that quotes the denial text stays a failure.
        let lookalike = UnlockError::from(UnlockError::Denied.to_string());
        assert!(!matches!(lookalike, UnlockError::Denied));
    }

    #[tokio::test]
    async fn panel_deny_ends_the_attempt_before_imk() {
        let started = std::time::Instant::now();
        let out = released(sh("sleep 20; printf pw"), panel_exiting(1), 1).await;
        assert!(matches!(out, Attempt::Denied));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn panel_countdown_fails_the_attempt() {
        let out = released(sh("sleep 20; printf pw"), panel_exiting(2), 1).await;
        assert!(matches!(out, Attempt::Failed));
    }

    #[tokio::test]
    async fn no_panel_exit_approves() {
        let out = released(sh("sleep 1; exit 1"), panel_exiting(0), 1).await;
        assert!(matches!(out, Attempt::Failed));
        match released(sh("sleep 1; printf pw"), panel_exiting(3), 1).await {
            Attempt::Released(m) => assert_eq!(m.as_str(), "pw"),
            _ => panic!("a failed panel must leave the touch gate alone"),
        }
    }

    #[test]
    fn unlock_panel_says_unlock_and_carries_no_command() {
        let json = serde_json::to_value(unlock_request()).unwrap();
        assert_eq!(json["unlock"], true);
        assert_eq!(json["provider"], "Bitwarden");
        assert_eq!(json["item"], MASTER_KEY_URL);
        assert!(json["agent"].is_null() && json["command"].is_null());
    }
}
