use std::process::Stdio;
use std::time::Duration;

use ap_client::{CredentialData, CredentialQuery};
use serde::Deserialize;
use tokio::process::Command;
use tracing::{info, warn};
use zeroize::Zeroizing;

// Absolute paths: a planted bw or imk earlier on PATH would otherwise receive
// the master password or the session.
const BW: &str = "/opt/homebrew/bin/bw";
const IMK: &str = "/usr/local/bin/imk";
const MASTER_KEY_URL: &str = "imk://api/bitwarden";
// At boot immurok's BLE link may not be up yet, so a failed `imk get` is retried.
const UNLOCK_ATTEMPTS: u32 = 5;
const UNLOCK_RETRY_DELAY: Duration = Duration::from_secs(10);

// immurok's overlay shows about two lines of the gated command and cuts the
// rest (measured with immurok 1.6.11), so the summary is kept short.
const SUMMARY_MAX_CHARS: usize = 60;

/// `--id <item>:?` asks for the item's custom field names, never their values,
/// so an agent can learn what to ask for next.
const LIST_FIELDS: &str = "?";
const LIST_FIELDS_LABEL: &str = "欄位名稱清單";

/// A credential and the line the approval overlay shows for it.
pub struct Found {
    pub credential: CredentialData,
    pub summary: String,
}

pub struct Vault {
    session: Zeroizing<String>,
}

impl Vault {
    pub async fn unlock() -> Result<Self, String> {
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
            ));
        }
        Ok(Self { session })
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

    /// Looks the item up, and on a miss syncs once and looks again, so items
    /// added on other devices are found without restarting.
    pub async fn lookup(&self, query: &CredentialQuery) -> Result<Option<Found>, String> {
        let (search, field) = target(query);
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
            let credential = match field {
                Some(LIST_FIELDS) => names_from_item(&out.stdout),
                Some(name) => {
                    let found = field_from_item(&out.stdout, name);
                    if found.is_none() {
                        info!(search, field = name, present = ?field_names(&out.stdout), "item has no such field");
                    }
                    found
                }
                None => credential_from_item(&out.stdout),
            };
            return Ok(credential.map(|credential| Found {
                credential,
                summary: summary(
                    item_name(&out.stdout).as_deref(),
                    field.map(|f| {
                        if f == LIST_FIELDS {
                            LIST_FIELDS_LABEL
                        } else {
                            f
                        }
                    }),
                ),
            }));
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("Not found") {
            Ok(None)
        } else {
            Err(format!("bw get item failed: {}", stderr.trim()))
        }
    }

    async fn bw(&self, args: &[&str]) -> Result<std::process::Output, String> {
        Command::new(BW)
            .args(args)
            .env("BW_SESSION", self.session.as_str())
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| format!("cannot run {BW}: {e}"))
    }
}

async fn master_password() -> Result<Zeroizing<String>, String> {
    for attempt in 1..=UNLOCK_ATTEMPTS {
        info!(attempt, "touch immurok to unlock Bitwarden");
        let out = Command::new(IMK)
            .args(["get", MASTER_KEY_URL])
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| format!("cannot run {IMK}: {e}"))?;
        let master = Zeroizing::new(
            String::from_utf8_lossy(&out.stdout)
                .trim_end_matches('\n')
                .to_string(),
        );
        if out.status.success() && !master.is_empty() {
            return Ok(master);
        }
        warn!(attempt, code = ?out.status.code(), "imk get failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        if attempt < UNLOCK_ATTEMPTS {
            tokio::time::sleep(UNLOCK_RETRY_DELAY).await;
        }
    }
    Err(format!(
        "immurok did not release {MASTER_KEY_URL} after {UNLOCK_ATTEMPTS} attempts"
    ))
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
    let names: Vec<String> = field_names(json)
        .into_iter()
        .filter(|n| !n.is_empty())
        .collect();
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

fn item_name(json: &[u8]) -> Option<String> {
    serde_json::from_slice::<BwItem>(json).ok()?.name
}

/// "<item name> / <field>", or "/ login" when the whole login is released.
/// The item name is cut first so the field always stays visible.
fn summary(item: Option<&str>, field: Option<&str>) -> String {
    let clean = |s: &str| s.chars().filter(|c| !c.is_control()).collect::<String>();
    let field = clean(field.unwrap_or("login"));
    let item = clean(item.unwrap_or("?"));
    let room = SUMMARY_MAX_CHARS
        .saturating_sub(field.chars().count() + 3)
        .max(8);
    let item = if item.chars().count() > room {
        item.chars().take(room - 1).chain(['…']).collect()
    } else {
        item
    };
    format!("{item} / {field}")
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

    #[test]
    fn summary_names_item_and_field() {
        assert_eq!(summary(Some("GitHub"), Some("token")), "GitHub / token");
        assert_eq!(summary(Some("GitHub"), None), "GitHub / login");
        assert_eq!(summary(None, None), "? / login");
    }

    #[test]
    fn summary_cuts_the_item_name_first_and_drops_control_chars() {
        let s = summary(Some(&"n".repeat(100)), Some("api\ntoken"));
        assert!(s.ends_with(" / apitoken"), "{s}");
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
}
