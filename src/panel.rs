//! The approval panel: a SwiftUI window shipped next to this binary that shows
//! what a request asks for while immurok waits for the touch.

use std::path::PathBuf;
use std::process::Stdio;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tracing::warn;

const BINARY: &str = "imk-aac-panel";

/// Sent as JSON on stdin, never argv, so other processes cannot read it.
#[derive(Serialize)]
pub struct Request<'a> {
    pub provider: &'a str,
    pub item: &'a str,
    pub field: &'a str,
    pub picked: bool,
    pub agent: &'a str,
    pub command: &'a str,
    pub timeout_secs: u64,
}

pub enum Outcome {
    Denied,
    TimedOut,
    /// Exited any other way (bad request, crash); the touch gate still holds.
    Failed(Option<i32>),
}

pub struct Panel(Child);

impl Panel {
    /// None when the panel cannot be shown; the touch gate then works alone.
    pub async fn show(request: &Request<'_>) -> Option<Self> {
        let path = match location() {
            Ok(p) => p,
            Err(e) => {
                warn!("cannot locate {BINARY}: {e}; touch gate alone");
                return None;
            }
        };
        let mut child = Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| warn!("cannot run {}: {e}; touch gate alone", path.display()))
            .ok()?;
        let json = serde_json::to_vec(request).ok()?;
        let mut stdin = child.stdin.take()?;
        if let Err(e) = stdin.write_all(&json).await {
            warn!("cannot send the request to {BINARY}: {e}; touch gate alone");
            return None;
        }
        Some(Self(child))
    }

    pub async fn close(mut self) {
        let _ = self.0.kill().await;
    }
}

/// Waits for the panel's answer; never resolves without a panel, so a select
/// on it leaves the touch gate alone.
pub async fn outcome(panel: &mut Option<Panel>) -> Outcome {
    let Some(Panel(child)) = panel else {
        return std::future::pending().await;
    };
    match child.wait().await.map(|s| s.code()) {
        Ok(Some(1)) => Outcome::Denied,
        Ok(Some(2)) => Outcome::TimedOut,
        Ok(code) => Outcome::Failed(code),
        Err(_) => Outcome::Failed(None),
    }
}

/// A sibling of the running binary, by absolute path: a planted panel earlier
/// on PATH could otherwise show the user a different request.
fn location() -> std::io::Result<PathBuf> {
    Ok(std::env::current_exe()?
        .canonicalize()?
        .with_file_name(BINARY))
}
