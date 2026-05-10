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
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

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

pub struct Sessiond {
    http_url: String,
    attach_addr: String,
    http: reqwest::Client,
}

impl Sessiond {
    pub fn new(http_url: String, attach_addr: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .no_hickory_dns()
            .build()
            .unwrap_or_else(|_| crate::system_http_client());
        Self {
            http_url,
            attach_addr,
            http,
        }
    }

    pub async fn call(&self, req: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let method = req
            .get("method")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("shell request missing method"))?;
        match method {
            "shell.list_recipes" => self.get_json("/api/recipes").await,
            "shell.list_sessions" => self.get_json("/api/sessions").await,
            "shell.create_session" => self.post_json("/api/sessions", &session_body(req)).await,
            "shell.replay_session" => {
                let id = required_str(&req, "id")?;
                self.get_json(&format!("/api/sessions/{id}/replay")).await
            }
            "shell.resize_session" => {
                let id = required_str(&req, "id")?;
                self.post_empty(
                    &format!("/api/sessions/{id}/resize"),
                    &serde_json::json!({
                        "cols": req.get("cols").and_then(|v| v.as_u64()).unwrap_or(80),
                        "rows": req.get("rows").and_then(|v| v.as_u64()).unwrap_or(24),
                    }),
                )
                .await
            }
            "shell.close_session" => {
                let id = required_str(&req, "id")?;
                self.post_empty(&format!("/api/sessions/{id}/close"), &serde_json::json!({}))
                    .await
            }
            other => anyhow::bail!("unsupported shell method: {other}"),
        }
    }

    pub async fn attach_stream(
        &self,
        req: serde_json::Value,
    ) -> anyhow::Result<(serde_json::Value, TcpStream)> {
        let id = required_str(&req, "id")?;
        let tail = req.get("tail").and_then(|v| v.as_bool()).unwrap_or(true);
        let mut stream = TcpStream::connect(&self.attach_addr).await?;
        let tail_arg = if tail { "tail" } else { "notail" };
        stream
            .write_all(format!("{id} {tail_arg}\n").as_bytes())
            .await?;
        Ok((
            serde_json::json!({
                "ok": true,
                "method": "shell.attach_session",
                "id": id,
                "tail": tail,
            }),
            stream,
        ))
    }

    async fn get_json(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let resp = self.http.get(self.url(path)).send().await?;
        decode_json(path, resp).await
    }

    async fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let resp = self.http.post(self.url(path)).json(body).send().await?;
        decode_json(path, resp).await
    }

    async fn post_empty(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let resp = self.http.post(self.url(path)).json(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("sessiond {path}: HTTP {status}: {body}");
        }
        Ok(serde_json::json!({"ok": true}))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.http_url.trim_end_matches('/'), path)
    }
}

fn session_body(req: serde_json::Value) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    for key in ["name", "recipe_id", "command", "cwd"] {
        if let Some(value) = req.get(key) {
            body.insert(key.to_string(), value.clone());
        }
    }
    serde_json::Value::Object(body)
}

fn required_str<'a>(req: &'a serde_json::Value, key: &str) -> anyhow::Result<&'a str> {
    req.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("shell request missing `{key}`"))
}

async fn decode_json(path: &str, resp: reqwest::Response) -> anyhow::Result<serde_json::Value> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("sessiond {path}: HTTP {status}: {body}");
    }
    Ok(resp.json().await?)
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
