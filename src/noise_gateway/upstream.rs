//! Unix-socket client for easyenclave's agent socket.
//!
//! Wire protocol: one request/response per unix stream. Each request
//! is a single line of JSON (`{"method": "...", ...}`) terminated by
//! `\n`; the response is one line of JSON. `EE_TOKEN` (if present in
//! the process env at boot) is injected into every request envelope.
//!
//! `attach_stream` is the exception — EE replies with a one-line ack
//! and then the socket carries raw PTY bytes bidirectionally until
//! either side closes. The returned tuple is `(ack_json, socket)`
//! and the caller is responsible for byte-bridging.

use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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
        self.inject_token(&mut req);

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

    /// Send an `attach`-shaped request, read the one-line ack, and
    /// return the socket so the caller can bridge raw PTY bytes. The
    /// ack is forwarded to the caller so the Noise-side client sees
    /// the same `{"ok": true, ...}` it would get from EE directly.
    ///
    /// Returns `Err` if EE's ack is `{"ok": false}` or malformed — in
    /// that case the caller should not start bridging and should pass
    /// the error back to the client as a normal one-shot response.
    pub async fn attach_stream(
        &self,
        mut req: serde_json::Value,
    ) -> anyhow::Result<(serde_json::Value, UnixStream)> {
        self.inject_token(&mut req);

        let mut stream = UnixStream::connect(&self.path).await?;
        let line = serde_json::to_vec(&req)?;
        stream.write_all(&line).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        // Read one line of ack byte-by-byte so the buffered reader
        // doesn't swallow subsequent raw-stream bytes.
        let mut ack = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match stream.read(&mut byte).await? {
                0 => anyhow::bail!("EE attach: closed before ack"),
                _ if byte[0] == b'\n' => break,
                _ if ack.len() > 4096 => anyhow::bail!("EE attach: ack too long"),
                _ => ack.push(byte[0]),
            }
        }
        let ack_val: serde_json::Value = serde_json::from_slice(&ack)?;
        if ack_val.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            anyhow::bail!("EE attach rejected: {ack_val}");
        }
        Ok((ack_val, stream))
    }

    fn inject_token(&self, req: &mut serde_json::Value) {
        if let Some(tok) = &self.token {
            if let Some(obj) = req.as_object_mut() {
                obj.insert("token".to_string(), serde_json::Value::String(tok.clone()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

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

    /// Fake EE that speaks the attach protocol: read one line, reply
    /// `{"ok": true}\n`, then echo raw bytes until the client closes.
    async fn spawn_attach_echo(path: PathBuf) {
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut one = [0u8; 1];
                    while stream.read_exact(&mut one).await.is_ok() {
                        if one[0] == b'\n' {
                            break;
                        }
                        req.push(one[0]);
                    }
                    let _ = stream.write_all(b"{\"ok\":true}\n").await;
                    let mut buf = [0u8; 64];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn attach_stream_reads_ack_and_echoes() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ee.sock");
        spawn_attach_echo(sock.clone()).await;
        let agent = EeAgent::new(sock.clone(), None);
        let (ack, mut stream) = agent
            .attach_stream(serde_json::json!({"method": "attach", "cmd": ["bash"]}))
            .await
            .unwrap();
        assert_eq!(ack["ok"], true);

        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn attach_stream_rejects_ok_false_ack() {
        // Server replies `{"ok": false, "reason": "nope"}` and closes.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ee.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut discard = [0u8; 1];
                while stream.read_exact(&mut discard).await.is_ok() && discard[0] != b'\n' {}
                let _ = stream
                    .write_all(b"{\"ok\":false,\"reason\":\"nope\"}\n")
                    .await;
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let agent = EeAgent::new(sock, None);
        let err = agent
            .attach_stream(serde_json::json!({"method": "attach"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rejected"), "got {err}");
    }
}
