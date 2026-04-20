//! EE capture listener (scaffold).
//!
//! Listens on a unix-domain socket for line-delimited JSON records
//! emitted by a patched easyenclave on each spawned workload's stdout
//! and stderr. Records look like:
//!
//! ```json
//! {"type":"spawn","id":"cloudflared-1735...","argv":[...],"cwd":"/"}
//! {"type":"out","id":"cloudflared-1735...","s":"stdout","b":"INF ..."}
//! {"type":"out","id":"cloudflared-1735...","s":"stderr","b":"..."}
//! {"type":"exit","id":"cloudflared-1735...","code":0}
//! ```
//!
//! **Status**: this file is a scaffold. It binds the socket, accepts
//! connections, and parses each record into [`CaptureRecord`] — but
//! it does not yet create [`crate::SessionInfo`]-shaped workload
//! sessions inside the [`crate::Manager`]. That comes in a follow-up
//! once upstream `easyenclave` is actually emitting these frames and
//! the SPA sidebar is ready to render the "Workloads" category.
//!
//! For now the listener just logs each parsed event to stderr so we
//! can verify the socket contract end-to-end once EE lands its patch.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

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
/// task that accepts connections and dispatches records.
///
/// Returns an error if the socket path's parent directory doesn't
/// exist or binding fails. A stale socket from a previous run is
/// removed automatically (unix sockets aren't self-cleaning on
/// process crash).
pub async fn spawn_listener(path: impl AsRef<Path>) -> std::io::Result<()> {
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
                    tokio::spawn(handle_connection(stream));
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

async fn handle_connection(stream: UnixStream) {
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
                    Ok(record) => handle_record(record),
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

fn handle_record(record: CaptureRecord) {
    // Scaffold: just log. Next PR wires these into `Manager` as
    // workload-kind sessions with their own ring buffer and block
    // stream so they render in the SPA sidebar alongside shells.
    match record {
        CaptureRecord::Spawn { id, argv, cwd } => {
            eprintln!(
                "capture: spawn id={id} argv={:?} cwd={:?}",
                argv,
                cwd.as_deref()
            );
        }
        CaptureRecord::Out { id, s, b } => {
            eprintln!("capture: out id={id} stream={s} bytes_len={}", b.len());
        }
        CaptureRecord::Exit { id, code } => {
            eprintln!("capture: exit id={id} code={code}");
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
