mod storage;

use ap_client::{
    ConnectionStore, CredentialData, CredentialRequestReply, DefaultProxyClient,
    FingerprintVerificationReply, UserClient, UserClientNotification, UserClientRequest,
};
use tokio::process::Command;
use tracing::{error, info, warn};

use storage::{FileConnectionCache, FileIdentityStorage};

// Same storage name as `aac listen`, so its identity and paired connections are reused.
const STORAGE_NAME: &str = "user_client";
const PROXY_URL: &str = "wss://ap.lesspassword.dev";
const IMK: &str = "/usr/local/bin/imk";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
                    tokio::spawn(async move {
                        let approved = touch_approved(&query.to_string()).await;
                        let _ = reply.send(CredentialRequestReply {
                            approved,
                            credential: approved.then(stub_credential),
                            credential_id: None,
                        });
                    });
                }
            },
            else => return Err("client event loop ended".into()),
        }
    }
}

async fn touch_approved(query: &str) -> bool {
    info!(query, "credential request; waiting for immurok touch");
    match Command::new(IMK)
        .args(["run", "--agent", "--", "/usr/bin/true"])
        .stdin(std::process::Stdio::null())
        .status()
        .await
    {
        Ok(status) if status.success() => {
            info!(query, "approved");
            true
        }
        Ok(status) => {
            warn!(query, code = ?status.code(), "denied");
            false
        }
        Err(e) => {
            error!(query, "cannot run {IMK}: {e}");
            false
        }
    }
}

// Stub credential source until M2 wires in Bitwarden.
fn stub_credential() -> CredentialData {
    CredentialData {
        username: Some("imk-aac-stub".to_string()),
        password: Some("imk-aac-stub-password".to_string().into()),
        totp: None,
        uri: None,
        notes: None,
        credential_id: None,
        domain: None,
    }
}
