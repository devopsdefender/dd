//! EE capture listener.
//!
//! Listens on a unix-domain socket for line-delimited JSON records
//! emitted by a patched easyenclave on each spawned workload's stdout
//! and stderr. Records look like:
//!
//! ```json
//! {"type":"spawn","id":"cloudflared-1735...","argv":[...],"cwd":null}
//! {"type":"out","id":"cloudflared-1735...","s":"stdout","b":"INF ..."}
//! {"type":"out","id":"cloudflared-1735...","s":"stderr","b":"..."}
//! {"type":"exit","id":"cloudflared-1735...","code":0}
//! ```
//!
//! Each connection is one workload lifetime. Records are dispatched
//! straight into [`crate::Manager`] as workload sessions:
//!
//! - `spawn` → [`crate::Manager::register_workload`]
//! - `out`   → [`crate::Manager::workload_out`]
//! - `exit`  → [`crate::Manager::workload_exit`]
//!
//! so the SPA sidebar's "Workloads" category populates live. Wire
//! contract upstream is documented in easyenclave's `capture.rs`
//! module.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::Manager;

/// One event over the EE capture socket.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CaptureRecord {
    /// EE has spawned a new workload process.
    Spawn {
        id: String,
        #[serde(default)]
        argv: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
    },
    /// A chunk of stdout or stderr bytes from a running workload.
    Out {
        id: String,
        /// "stdout" | "stderr"
        #[serde(default = "default_stdout")]
        s: String,
        /// Bytes. EE can send base64 or raw UTF-8; we tolerate both.
        b: String,
    },
    /// The workload has exited.
    Exit { id: String, code: i32 },
}

fn default_stdout() -> String {
    "stdout".into()
}

/// Remove any stale socket at `path`, bind a fresh one, and spawn a
/// task that accepts connections and dispatches records into
/// `manager` as workload sessions.
///
/// Returns an error if the socket path's parent directory doesn't
/// exist or binding fails. A stale socket from a previous run is
/// removed automatically (unix sockets aren't self-cleaning on
/// process crash).
pub async fn spawn_listener(path: impl AsRef<Path>, manager: Manager) -> std::io::Result<()> {
    let path: PathBuf = path.as_ref().to_path_buf();
    // `bind(2)` on a unix socket ENOENTs if the parent dir is missing.
    // On the DD agent VM, `/run/ee/` is the conventional capture-socket
    // dir but nothing creates it — so we do it ourselves. Idempotent.
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    // Unix sockets linger after the owning process dies; clean up
    // before rebinding.
    if tokio::fs::metadata(&path).await.is_ok() {
        let _ = tokio::fs::remove_file(&path).await;
    }
    let listener = UnixListener::bind(&path)?;
    eprintln!("capture: listening on {}", path.display());

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(handle_connection(stream, manager.clone()));
                }
                Err(e) => {
                    eprintln!("capture: accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        }
    });
    Ok(())
}

async fn handle_connection(stream: UnixStream, manager: Manager) {
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<CaptureRecord>(line) {
                    Ok(record) => handle_record(record, &manager).await,
                    Err(e) => eprintln!("capture: parse error ({e}) on line: {line}"),
                }
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("capture: read error: {e}");
                break;
            }
        }
    }
}

async fn handle_record(record: CaptureRecord, manager: &Manager) {
    match record {
        CaptureRecord::Spawn { id, argv, cwd } => {
            manager.register_workload(id, argv, cwd).await;
        }
        CaptureRecord::Out { id, s: _, b } => {
            // EE sends lines without the trailing newline; replace it
            // so the rolling ring produces readable replay in xterm.js.
            let mut bytes = b.into_bytes();
            bytes.push(b'\n');
            manager.workload_out(&id, &bytes).await;
        }
        CaptureRecord::Exit { id, code } => {
            manager.workload_exit(&id, code).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spawn_record() {
        let line =
            r#"{"type":"spawn","id":"cloudflared-1","argv":["cloudflared","tunnel"],"cwd":"/"}"#;
        let rec: CaptureRecord = serde_json::from_str(line).unwrap();
        match rec {
            CaptureRecord::Spawn { id, argv, cwd } => {
                assert_eq!(id, "cloudflared-1");
                assert_eq!(argv, vec!["cloudflared", "tunnel"]);
                assert_eq!(cwd.as_deref(), Some("/"));
            }
            _ => panic!("expected Spawn"),
        }
    }

    #[test]
    fn parses_out_record() {
        let line = r#"{"type":"out","id":"nv-1","s":"stderr","b":"boom\n"}"#;
        let rec: CaptureRecord = serde_json::from_str(line).unwrap();
        match rec {
            CaptureRecord::Out { id, s, b } => {
                assert_eq!(id, "nv-1");
                assert_eq!(s, "stderr");
                assert_eq!(b, "boom\n");
            }
            _ => panic!("expected Out"),
        }
    }

    #[test]
    fn parses_exit_record() {
        let line = r#"{"type":"exit","id":"x","code":137}"#;
        let rec: CaptureRecord = serde_json::from_str(line).unwrap();
        match rec {
            CaptureRecord::Exit { id, code } => {
                assert_eq!(id, "x");
                assert_eq!(code, 137);
            }
            _ => panic!("expected Exit"),
        }
    }

    #[test]
    fn out_defaults_to_stdout_when_stream_omitted() {
        let line = r#"{"type":"out","id":"x","b":"hi"}"#;
        let rec: CaptureRecord = serde_json::from_str(line).unwrap();
        if let CaptureRecord::Out { s, .. } = rec {
            assert_eq!(s, "stdout");
        } else {
            panic!("expected Out");
        }
    }
}
