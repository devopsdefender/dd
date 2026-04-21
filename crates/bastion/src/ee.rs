//! Minimal easyenclave unix-socket client.
//!
//! Bastion uses this to *pull* workload state from EE on startup
//! (and periodically after), backfilling boot workloads that spawn
//! too early to be captured by the push path on
//! `/run/ee/capture.sock`. Parallels
//! [`devopsdefender`'s DD-side client](../../dd/src/ee.rs) — same
//! wire protocol, same `EE_TOKEN` passthrough.
//!
//! Public surface intentionally tiny: `list` + `logs`, which is all
//! [`ee_sync`](crate::ee_sync) needs to seed the
//! [`Manager`](crate::Manager).
//!
//! Seal-aware: reads `EE_TOKEN` once at construction and injects
//! `"token": "<hex>"` into every request. Requires the hosting
//! `workload.json.tmpl` to set `"inherit_token": true` so EE hands
//! bastion the token in its env.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// One deployment as reported by EE's `list` method. Field set is
/// the intersection of what EE emits and what bastion cares about —
/// extra EE fields are tolerated by serde and discarded.
#[derive(Debug, Clone, Deserialize)]
pub struct Deployment {
    pub id: String,
    pub app_name: String,
    pub status: String,
    #[serde(default)]
    pub source: Option<String>,
}

pub struct EeClient {
    path: PathBuf,
    token: Option<String>,
}

impl EeClient {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            token: std::env::var("EE_TOKEN").ok().filter(|s| !s.is_empty()),
        }
    }

    async fn call(&self, mut req: Value) -> std::io::Result<Value> {
        if let Some(t) = &self.token {
            req["token"] = Value::String(t.clone());
        }
        let stream = UnixStream::connect(&self.path).await?;
        let (rd, mut wr) = stream.into_split();
        let mut buf = serde_json::to_vec(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        buf.push(b'\n');
        wr.write_all(&buf).await?;
        wr.shutdown().await?;

        let mut line = String::new();
        BufReader::new(rd).read_line(&mut line).await?;
        serde_json::from_str(line.trim())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// `{"method":"list"}` → `deployments[]`.
    pub async fn list(&self) -> std::io::Result<Vec<Deployment>> {
        let resp = self.call(serde_json::json!({"method": "list"})).await?;
        let arr = resp
            .get("deployments")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(arr
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect())
    }

    /// `{"method":"logs","id":<id>,"tail":<n>}` → lines[].
    /// `tail` caps how much history EE hands back; 1000 is typically
    /// the whole file for well-behaved workloads.
    pub async fn logs(&self, id: &str, tail: usize) -> std::io::Result<Vec<String>> {
        let resp = self
            .call(serde_json::json!({"method": "logs", "id": id, "tail": tail}))
            .await?;
        Ok(resp
            .get("lines")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }
}
