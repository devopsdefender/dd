//! Unix socket client for the easyenclave API.
//!
//! Each method opens a short-lived connection, sends a JSON request
//! (newline-delimited), reads one JSON response line, and disconnects.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

    /// Send a JSON request and read one JSON response line.
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
        self.request(serde_json::json!({ "action": "health" }))
            .await
    }

    /// Request a TDX attestation quote with the given nonce.
    pub async fn attest(&self, nonce: &str) -> Result<serde_json::Value, String> {
        self.request(serde_json::json!({ "action": "attest", "nonce": nonce }))
            .await
    }

    /// Deploy a workload.
    pub async fn deploy(&self, req: serde_json::Value) -> Result<serde_json::Value, String> {
        let mut payload = req;
        payload["action"] = serde_json::json!("deploy");
        self.request(payload).await
    }

    /// Stop a workload by id.
    pub async fn stop(&self, id: &str) -> Result<serde_json::Value, String> {
        self.request(serde_json::json!({ "action": "stop", "id": id }))
            .await
    }

    /// Execute a command with a timeout.
    pub async fn exec(
        &self,
        cmd: &[String],
        timeout_secs: u64,
    ) -> Result<serde_json::Value, String> {
        self.request(serde_json::json!({
            "action": "exec",
            "cmd": cmd,
            "timeout_secs": timeout_secs,
        }))
        .await
    }

    /// List running workloads.
    pub async fn list(&self) -> Result<serde_json::Value, String> {
        self.request(serde_json::json!({ "action": "list" })).await
    }

    /// Get logs for a workload by id.
    pub async fn logs(&self, id: &str) -> Result<serde_json::Value, String> {
        self.request(serde_json::json!({ "action": "logs", "id": id }))
            .await
    }
}
