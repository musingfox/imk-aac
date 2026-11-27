mod bitwarden;
mod overlay;
mod panel;
mod picker;
mod requester;
mod storage;

use std::sync::Arc;

use ap_client::{
    ConnectionStore, CredentialRequestReply, DefaultProxyClient, FingerprintVerificationReply,
    UserClient, UserClientNotification, UserClientRequest,
};
use tracing::{error, info, warn};

use bitwarden::{Found, UnlockError, Vault};
use panel::{Outcome, Panel};
use picker::Picker;
use requester::Requester;
use storage::{FileConnectionCache, FileIdentityStorage};

// Same storage name as `aac listen`, so its identity and paired connections are reused.
const STORAGE_NAME: &str = "user_client";
const PROXY_URL: &str = "wss://ap.lesspassword.dev";
const IMK: &str = "/usr/local/bin/imk";
const PROVIDER: &str = "Bitwarden";
// How long `imk run --agent` waits for a touch (measured), so the panel's
// countdown ends with it.
const TOUCH_TIMEOUT_SECS: u64 = 30;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Before any runtime or logging: this copy only exists to become imk get.
    if overlay::gated_self(bitwarden::UNLOCK_TEXT) {
        return Err(bitwarden::exec_master_key_get().into());
    }
    serve()
}

#[tokio::main]
async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    if FileIdentityStorage::load_fingerprint(STORAGE_NAME)?.is_none() {
        return Err("no identity in ~/.access-protocol; pair once with `aac listen` first".into());
    }
    let identity = Box::new(FileIdentityStorage::load_or_generate(STORAGE_NAME)?);
    let connections = FileConnectionCache::load_or_create(STORAGE_NAME)?;
    let paired = connections.list().await.len();
    if paired == 0 {
        return Err("no paired connection; pair once with `aac listen` first".into());
    }

    let picker = Picker::from_env().unwrap_or_else(|e| {
        warn!("field picking stays off: {e}");
        None
    });
    info!(enabled = picker.is_some(), "field picking");
    let vault = match Vault::unlock(picker).await {
        Ok(vault) => Arc::new(vault),
        // Exit 0 so launchd's KeepAlive SuccessfulExit=false does not relaunch
        // and ask for the fingerprint again after a deliberate no.
        Err(UnlockError::Denied) => {
            warn!("Bitwarden unlock denied in the approval panel; exiting without a listener");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    vault.boot_sync().await;

    let proxy = Box::new(DefaultProxyClient::from_url(PROXY_URL.to_string()));
    // No PSK store and no token requests: this listener never opens a new pairing.
    let handle = UserClient::connect(identity, Box::new(connections), proxy, None, None).await?;
    let _client = handle.client;
    let mut notifications = handle.notifications;
    let mut requests = handle.requests;
    info!(paired, "listening");

    loop {
        tokio::select! {
            Some(n) = notifications.recv() => match n {
                UserClientNotification::Error { message, context } => error!(?context, "{message}"),
                other => info!(?other, "notification"),
            },
            Some(r) = requests.recv() => match r {
                UserClientRequest::VerifyFingerprint { reply, .. } => {
                    warn!("rejected new pairing; pair with `aac listen` instead");
                    let _ = reply.send(FingerprintVerificationReply { approved: false, name: None });
                }
                UserClientRequest::CredentialRequest { query, reply, .. } => {
                    let vault = Arc::clone(&vault);
                    tokio::spawn(async move {
                        let label = query.to_string();
                        let found = match vault.lookup(&query).await {
                            Ok(Some(f)) => Some(f),
                            Ok(None) => {
                                warn!(query = label, "not found in vault; denied without asking");
                                None
                            }
                            Err(e) => {
                                error!(query = label, "{e}");
                                None
                            }
                        };
                        let credential = match found {
                            Some(f) => {
                                // Display only: argv and process names can be forged by any
                                // local process, so the requester never decides approval.
                                let requester = requester::detect(&query).await;
                                if touch_approved(&label, &f, &requester).await {
                                    Some(f.credential)
                                } else {
                                    None
                                }
                            }
                            None => None,
                        };
                        let credential_id = credential.as_ref().and_then(|c| c.credential_id.clone());
                        let _ = reply.send(CredentialRequestReply {
                            approved: credential.is_some(),
                            credential,
                            credential_id,
                        });
                    });
                }
            },
            else => return Err("client event loop ended".into()),
        }
    }
}

/// The touch on immurok approves, as before; the panel can only deny, by its
/// Deny button or when its countdown ends.
async fn touch_approved(query: &str, found: &Found, requester: &Requester) -> bool {
    let summary = found.summary();
    info!(
        query,
        summary, "credential request; waiting for immurok touch"
    );
    let mut imk = match overlay::imk_run(IMK, &summary)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            error!(query, "cannot run {IMK}: {e}");
            return false;
        }
    };
    let mut panel = Panel::show(&panel::Request {
        provider: PROVIDER,
        item: &found.item,
        field: &found.field,
        picked: found.picked,
        origin: requester.origin(),
        agent: match requester {
            Requester::Local { agent, .. } => agent.as_deref(),
            _ => None,
        },
        command: match requester {
            Requester::Local { command, .. } => command.as_deref(),
            _ => None,
        },
        query,
        timeout_secs: TOUCH_TIMEOUT_SECS,
        unlock: false,
    })
    .await;
    loop {
        tokio::select! {
            status = imk.wait() => {
                if let Some(p) = panel.take() {
                    p.close().await;
                }
                return match status {
                    Ok(status) if status.success() => {
                        info!(query, "approved");
                        true
                    }
                    Ok(status) => {
                        warn!(query, code = ?status.code(), "denied");
                        false
                    }
                    Err(e) => {
                        error!(query, "cannot wait for {IMK}: {e}");
                        false
                    }
                };
            }
            outcome = panel::outcome(&mut panel) => match outcome {
                Outcome::Denied | Outcome::TimedOut => {
                    let _ = imk.kill().await;
                    if matches!(outcome, Outcome::Denied) {
                        warn!(query, "denied by user");
                    } else {
                        warn!(query, "timed out");
                    }
                    return false;
                }
                Outcome::Failed(code) => {
                    warn!(query, ?code, "approval panel failed; touch gate alone");
                    panel = None;
                }
            },
        }
    }
}
