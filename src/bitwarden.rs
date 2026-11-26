use std::process::Stdio;
use std::time::Duration;

use ap_client::CredentialData;
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
    pub async fn lookup(&self, search: &str) -> Result<Option<CredentialData>, String> {
        if let Some(c) = self.get(search).await? {
            return Ok(Some(c));
        }
        info!(search, "not found; syncing and retrying");
        self.sync().await?;
        self.get(search).await
    }

    async fn get(&self, search: &str) -> Result<Option<CredentialData>, String> {
        let out = self.bw(&["get", "item", search]).await?;
        if out.status.success() {
            return Ok(credential_from_item(&out.stdout));
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

#[derive(Deserialize)]
struct BwItem {
    id: Option<String>,
    login: Option<BwLogin>,
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
}
