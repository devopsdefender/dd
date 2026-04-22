//! Unix-socket client for easyenclave's agent socket.
//!
//! Wire protocol: one request/response per TCP-like unix stream.
//! Each request is a single line of JSON (`{"method": "...", ...}`)
//! terminated by `\n`; the response is one line of JSON. `EE_TOKEN`
//! (if present at boot) is injected into every request envelope.

use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub const DEFAULT_EE_AGENT_SOCK: &str = "/var/lib/easyenclave/agent.sock";

pub struct EeAgent {
    path: PathBuf,
    token: Option<String>,
}

impl EeAgent {
    pub fn new(path: PathBuf, token: Option<String>) -> Self {
        Self { path, token }
    }

    /// Forward a request envelope to EE's agent socket, injecting the
    /// `token` field if one was supplied at boot. Returns EE's raw
    /// response value.
    pub async fn call(&self, mut req: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        if let Some(tok) = &self.token {
            if let Some(obj) = req.as_object_mut() {
                obj.insert("token".to_string(), serde_json::Value::String(tok.clone()));
            }
        }

        let mut stream = UnixStream::connect(&self.path).await?;
        let line = serde_json::to_vec(&req)?;
        stream.write_all(&line).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut resp = String::new();
        reader.read_line(&mut resp).await?;
        let value: serde_json::Value = serde_json::from_str(resp.trim_end())?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// Spawn a fake EE agent socket that echoes each request back with
    /// its captured `token` field visible, so tests can assert the
    /// proxy injected it.
    async fn spawn_echo(path: PathBuf) {
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut one = [0u8; 1];
                    while stream.read_exact(&mut one).await.is_ok() {
                        if one[0] == b'\n' {
                            break;
                        }
                        buf.push(one[0]);
                    }
                    let req: serde_json::Value =
                        serde_json::from_slice(&buf).unwrap_or(serde_json::json!({}));
                    let resp = serde_json::json!({ "echo": req });
                    let mut line = serde_json::to_vec(&resp).unwrap();
                    line.push(b'\n');
                    let _ = stream.write_all(&line).await;
                });
            }
        });
        // Give the listener a beat to bind.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn injects_token() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ee.sock");
        spawn_echo(sock.clone()).await;

        let agent = EeAgent::new(sock.clone(), Some("deadbeef".into()));
        let resp = agent
            .call(serde_json::json!({"method": "list"}))
            .await
            .unwrap();
        assert_eq!(resp["echo"]["token"], "deadbeef");
        assert_eq!(resp["echo"]["method"], "list");
    }

    #[tokio::test]
    async fn omits_token_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ee.sock");
        spawn_echo(sock.clone()).await;

        let agent = EeAgent::new(sock.clone(), None);
        let resp = agent
            .call(serde_json::json!({"method": "list"}))
            .await
            .unwrap();
        assert!(resp["echo"].get("token").is_none());
    }
}
