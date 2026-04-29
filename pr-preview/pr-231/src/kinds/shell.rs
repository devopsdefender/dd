//! Shell kind.
//!
//! Per-user attested bash over the web. Browser opens a WebSocket to
//! `/session/shell`; the agent verifies the `dd_session` JWT cookie
//! (auth.rs middleware), checks the GitHub login is in
//! `kind_config.allowed_users` (or that the list is empty = "any
//! authenticated user is fine"), then opens an EE `attach()` PTY
//! socket and shuttles bytes between WS frames and the unix socket.
//!
//! Session TTL is enforced by tearing down the WS at `session_ttl_secs`
//! even if the user is still typing.

use axum::extract::ws::{Message, WebSocket};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::auth::Identity;
use crate::workload::{KindConfig, Workload};

#[derive(Debug, Clone)]
pub struct ShellPolicy {
    pub session_ttl: Duration,
    pub allowed_users: Vec<String>,
}

impl ShellPolicy {
    pub fn from_workload(w: &Workload) -> Option<Self> {
        match &w.kind_config {
            KindConfig::Shell {
                session_ttl_secs,
                allowed_users,
                ..
            } => Some(Self {
                session_ttl: Duration::from_secs(*session_ttl_secs),
                allowed_users: allowed_users.clone(),
            }),
            _ => None,
        }
    }

    pub fn permits(&self, ident: &Identity) -> bool {
        if self.allowed_users.is_empty() {
            return true;
        }
        self.allowed_users
            .iter()
            .any(|u| u.eq_ignore_ascii_case(&ident.claims.sub))
    }
}

/// Bridge an axum WebSocket to an EE-attached PTY. Closes when either
/// side closes, or when `policy.session_ttl` elapses.
pub async fn bridge_pty(mut ws: WebSocket, mut pty: UnixStream, policy: ShellPolicy) {
    let deadline = tokio::time::sleep(policy.session_ttl);
    tokio::pin!(deadline);
    let (mut pty_rd, mut pty_wr) = pty.split();
    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            _ = &mut deadline => {
                let _ = ws.send(Message::Close(None)).await;
                break;
            }
            msg = ws.recv() => match msg {
                Some(Ok(Message::Binary(b))) => {
                    if pty_wr.write_all(&b).await.is_err() { break; }
                }
                Some(Ok(Message::Text(t))) => {
                    if pty_wr.write_all(t.as_bytes()).await.is_err() { break; }
                }
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },
            n = pty_rd.read(&mut buf) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
            },
        }
    }
    let _ = pty.shutdown().await;
}
