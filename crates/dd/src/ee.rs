//! Unix-socket client for the easyenclave daemon.
//!
//! Newline-delimited JSON request/response, one exchange per connection.
//! `attach()` is special — after the JSON ack the socket carries raw PTY bytes.

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::error::{Error, Result};

pub struct Ee {
    path: String,
    /// Boot token minted by easyenclave and handed to dd-agent via
    /// `EE_TOKEN`. When set, every socket request carries
    /// `"token": "<hex>"` so EE's seal (easyenclave#80) accepts us.
    /// On unpatched EE images the field is ignored as an unknown key;
    /// makes this change forward-compatible either direction.
    token: Option<String>,
}

impl Ee {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            token: std::env::var("EE_TOKEN").ok().filter(|s| !s.is_empty()),
        }
    }

    async fn call(&self, mut req: serde_json::Value) -> Result<serde_json::Value> {
        if let Some(token) = &self.token {
            req["token"] = serde_json::Value::String(token.clone());
        }

        let stream = UnixStream::connect(&self.path)
            .await
            .map_err(|e| Error::Upstream(format!("EE connect {}: {e}", self.path)))?;
        let (rd, mut wr) = stream.into_split();

        let mut buf = serde_json::to_vec(&req)?;
        buf.push(b'\n');
        wr.write_all(&buf).await?;
        wr.shutdown().await?;

        let mut line = String::new();
        BufReader::new(rd).read_line(&mut line).await?;
        Ok(serde_json::from_str(line.trim())?)
    }

    pub async fn health(&self) -> Result<serde_json::Value> {
        self.call(serde_json::json!({"method": "health"})).await
    }

    pub async fn list(&self) -> Result<serde_json::Value> {
        self.call(serde_json::json!({"method": "list"})).await
    }

    pub async fn logs(&self, id: &str) -> Result<serde_json::Value> {
        self.call(serde_json::json!({"method": "logs", "id": id}))
            .await
    }

    pub async fn attest(&self, nonce: &str) -> Result<serde_json::Value> {
        self.call(serde_json::json!({"method": "attest", "nonce": nonce}))
            .await
    }

    /// TDX attestation with caller-supplied 64-byte `REPORT_DATA`
    /// (base64). Used to bind the Noise static pubkey into the
    /// quote so a client can verify `sha256(noise_pubkey)` matches
    /// the hardware-attested value. `data` must be ≤64 bytes; EE
    /// rejects longer.
    pub async fn attest_with_report_data(&self, data_b64: &str) -> Result<serde_json::Value> {
        self.call(serde_json::json!({
            "method": "attest",
            "report_data_b64": data_b64,
        }))
        .await
    }

    /// Deploy a workload at runtime. Spec is a workload object
    /// (`app_name`, `github_release`/`cmd`, `env`, ...) — we just set
    /// `method` and forward.
    pub async fn deploy(&self, mut spec: serde_json::Value) -> Result<serde_json::Value> {
        spec["method"] = serde_json::json!("deploy");
        self.call(spec).await
    }

    /// Run a command inside the enclave and capture stdout/stderr.
    pub async fn exec(&self, cmd: &[String], timeout_secs: u64) -> Result<serde_json::Value> {
        self.call(serde_json::json!({
            "method": "exec",
            "cmd": cmd,
            "timeout_secs": timeout_secs,
        }))
        .await
    }

    /// Open a PTY shell. Sends the attach request, reads the ack, returns
    /// the raw stream for byte bridging to a WebSocket.
    pub async fn attach(&self, cmd: &[String]) -> Result<UnixStream> {
        let mut stream = UnixStream::connect(&self.path)
            .await
            .map_err(|e| Error::Upstream(format!("EE attach {}: {e}", self.path)))?;

        let mut req = serde_json::json!({"method": "attach", "cmd": cmd});
        if let Some(token) = &self.token {
            req["token"] = serde_json::Value::String(token.clone());
        }
        let mut buf = serde_json::to_vec(&req)?;
        buf.push(b'\n');
        stream.write_all(&buf).await?;

        // Read one line (the ack) without buffering — next bytes belong to the caller.
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match stream.read(&mut byte).await? {
                0 => return Err(Error::Upstream("EE attach: closed before ack".into())),
                _ if byte[0] == b'\n' => break,
                _ if line.len() > 4096 => {
                    return Err(Error::Upstream("EE attach: ack too long".into()))
                }
                _ => line.push(byte[0]),
            }
        }
        let ack: serde_json::Value = serde_json::from_slice(&line)?;
        if ack["ok"].as_bool() != Some(true) {
            return Err(Error::Upstream(format!("EE attach rejected: {ack}")));
        }
        Ok(stream)
    }
}
