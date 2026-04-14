//! Unix socket client for the easyenclave API.
//!
//! Most methods open a short-lived connection, send a JSON request
//! (newline-delimited), read one JSON response line, and disconnect.
//! `attach` is the exception — it sends the JSON handshake and then
//! returns the live stream so the caller can bridge raw bytes (PTY
//! shell sessions over WebSocket).

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Client for the easyenclave daemon over a Unix socket.
pub struct EeClient {
    socket_path: String,
}

impl EeClient {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
        }
    }

    /// Send a JSON request and read one JSON response line. The socket
    /// dispatches on a `method` field, not `action`.
    async fn request(&self, req: serde_json::Value) -> Result<serde_json::Value, String> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| format!("connect to {}: {e}", self.socket_path))?;

        let (reader, mut writer) = stream.into_split();

        let mut payload = serde_json::to_vec(&req).map_err(|e| format!("serialize: {e}"))?;
        payload.push(b'\n');
        writer
            .write_all(&payload)
            .await
            .map_err(|e| format!("write: {e}"))?;
        writer
            .shutdown()
            .await
            .map_err(|e| format!("shutdown write: {e}"))?;

        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        buf_reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("read response: {e}"))?;

        serde_json::from_str(line.trim()).map_err(|e| format!("parse response: {e}"))
    }

    /// Health check.
    pub async fn health(&self) -> Result<serde_json::Value, String> {
        self.request(serde_json::json!({ "method": "health" }))
            .await
    }

    /// Request a TDX attestation quote with the given nonce.
    pub async fn attest(&self, nonce: &str) -> Result<serde_json::Value, String> {
        self.request(serde_json::json!({ "method": "attest", "nonce": nonce }))
            .await
    }

    /// Deploy a workload.
    pub async fn deploy(&self, req: serde_json::Value) -> Result<serde_json::Value, String> {
        let mut payload = req;
        payload["method"] = serde_json::json!("deploy");
        self.request(payload).await
    }

    /// Stop a workload by id.
    pub async fn stop(&self, id: &str) -> Result<serde_json::Value, String> {
        self.request(serde_json::json!({ "method": "stop", "id": id }))
            .await
    }

    /// Execute a command with a timeout.
    pub async fn exec(
        &self,
        cmd: &[String],
        timeout_secs: u64,
    ) -> Result<serde_json::Value, String> {
        self.request(serde_json::json!({
            "method": "exec",
            "cmd": cmd,
            "timeout_secs": timeout_secs,
        }))
        .await
    }

    /// List running workloads.
    pub async fn list(&self) -> Result<serde_json::Value, String> {
        self.request(serde_json::json!({ "method": "list" })).await
    }

    /// Get logs for a workload by id.
    pub async fn logs(&self, id: &str) -> Result<serde_json::Value, String> {
        self.request(serde_json::json!({ "method": "logs", "id": id }))
            .await
    }

    /// Open an interactive PTY shell on the easyenclave socket.
    ///
    /// Sends `{"method":"attach","cmd":[...]}`, reads the JSON ack, and
    /// returns the live `UnixStream` so the caller can bridge raw bytes
    /// in both directions (typically to a WebSocket). After this call,
    /// the socket connection is in raw byte-stream mode — no more JSON.
    ///
    /// `cmd` defaults to `["/bin/sh"]` server-side if empty.
    pub async fn attach(&self, cmd: &[String]) -> Result<UnixStream, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| format!("connect to {}: {e}", self.socket_path))?;

        let req = serde_json::json!({ "method": "attach", "cmd": cmd });
        let mut payload = serde_json::to_vec(&req).map_err(|e| format!("serialize: {e}"))?;
        payload.push(b'\n');
        stream
            .write_all(&payload)
            .await
            .map_err(|e| format!("write attach: {e}"))?;

        // Read exactly one line (the ack) from the stream without
        // consuming any bytes after the newline. Manual byte loop so we
        // don't pull a `BufReader` over the stream — that would buffer
        // server-pushed bytes the caller hasn't asked for yet.
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = stream
                .read(&mut byte)
                .await
                .map_err(|e| format!("read ack: {e}"))?;
            if n == 0 {
                return Err("attach ack EOF".into());
            }
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
            if line.len() > 4096 {
                return Err("attach ack too long".into());
            }
        }

        let ack: serde_json::Value = serde_json::from_slice(&line)
            .map_err(|e| format!("parse ack {:?}: {e}", String::from_utf8_lossy(&line)))?;
        if ack["ok"].as_bool() != Some(true) || ack["attached"].as_bool() != Some(true) {
            return Err(format!("attach refused: {ack}"));
        }

        Ok(stream)
    }
}
