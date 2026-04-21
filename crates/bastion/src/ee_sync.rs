//! Bootstrap the [`Manager`] from EE's view of the world.
//!
//! The capture socket (`/run/ee/capture.sock`) is the real-time
//! push path — it catches every workload EE spawns *after* bastion
//! binds the listener. Boot workloads race that binding, so they're
//! invisible to push. This module closes that gap: on startup we
//! pull the full deployment list from EE's unix socket via
//! [`EeClient`](crate::ee::EeClient), fetch each one's log tail,
//! and feed both into [`Manager`] so every workload — boot and
//! post-boot — appears in the sidebar from the first render.
//!
//! Deduplication is handled by `Manager::register_workload` (already
//! idempotent on `id`), so running this concurrently with the push
//! listener is safe.

use std::path::Path;
use std::time::Duration;

use crate::ee::{Deployment, EeClient};
use crate::Manager;

/// Default `tail` for the per-workload log backfill. 1000 lines is
/// typically more than `RING_CAP` / line would be anyway, and EE
/// caps internally at file length, so this is effectively "give me
/// everything you have."
const BACKFILL_TAIL: usize = 1000;

/// Re-poll every 30 s. Cheap safety net for push failures; also
/// picks up state transitions (e.g. a running workload turning
/// `completed`) that the push path might miss if its capture
/// connection was never established.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Status values EE emits that mean "not running anymore" — we
/// commit a closing `BlockRecord` for each via `workload_exit`.
fn is_terminal(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "stopped")
}

/// EE reports exit status as a string; map it back to a code the
/// `BlockRecord` schema expects. `completed` → 0, everything else
/// non-zero but distinct for visual grouping.
fn status_to_code(status: &str) -> i32 {
    match status {
        "completed" => 0,
        "stopped" => 143,
        _ => -1,
    }
}

/// Run one pull cycle: for every deployment EE knows about, make
/// sure the [`Manager`] has a matching workload session (registered,
/// log-seeded, and possibly exit-committed). Safe to call repeatedly.
pub async fn sync_once(manager: &Manager, ee: &EeClient) {
    let deployments = match ee.list().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ee_sync: list failed: {e}");
            return;
        }
    };
    for dep in deployments {
        register_and_fill(manager, ee, &dep).await;
    }
}

async fn register_and_fill(manager: &Manager, ee: &EeClient, dep: &Deployment) {
    // argv from EE's `source` (either "owner/repo@tag" or
    // "program args…") — we don't have the real argv on EE's side,
    // so this is the best label we can give the sidebar.
    let argv: Vec<String> = dep
        .source
        .as_deref()
        .unwrap_or(dep.app_name.as_str())
        .split_whitespace()
        .map(String::from)
        .collect();
    let id = format!("{}-{}", dep.app_name, dep.id);
    manager.register_workload(id.clone(), argv, None).await;

    // Seed the per-lifetime accumulator with the file tail EE has
    // captured so far. This is what makes cloudflared / podman /
    // the whole boot set show real history instead of just a name.
    match ee.logs(&dep.id, BACKFILL_TAIL).await {
        Ok(lines) => {
            for line in lines {
                let mut bytes = line.into_bytes();
                bytes.push(b'\n');
                manager.workload_out(&id, &bytes).await;
            }
        }
        Err(e) => eprintln!("ee_sync: logs({}) failed: {e}", dep.id),
    }

    if is_terminal(&dep.status) {
        manager
            .workload_exit(&id, status_to_code(&dep.status))
            .await;
    }
}

/// Spawn the bootstrap pull + periodic re-sync. Returns immediately;
/// the actual work runs in a tokio task so the caller can continue
/// booting bastion (HTTP listener, capture socket, etc.) without
/// blocking on EE round-trips.
pub fn start(manager: Manager, socket_path: impl AsRef<Path>) {
    let ee = EeClient::new(socket_path);
    tokio::spawn(async move {
        sync_once(&manager, &ee).await;
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            sync_once(&manager, &ee).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    /// Minimal fake EE that serves canned `list` + `logs` responses
    /// so we can exercise `sync_once` end-to-end without a real
    /// easyenclave.
    async fn spawn_fake_ee(
        dir: &TempDir,
        list_resp: serde_json::Value,
        logs_responses: Arc<std::collections::HashMap<String, serde_json::Value>>,
    ) -> std::path::PathBuf {
        let sock = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let list_resp = list_resp.clone();
                let logs_responses = logs_responses.clone();
                tokio::spawn(async move {
                    let (rd, mut wr) = stream.into_split();
                    let mut lines = BufReader::new(rd).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let req: serde_json::Value =
                            serde_json::from_str(&line).unwrap_or_default();
                        let method = req
                            .get("method")
                            .and_then(|m| m.as_str())
                            .unwrap_or_default();
                        let resp = match method {
                            "list" => list_resp.clone(),
                            "logs" => {
                                let id = req.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                                logs_responses
                                    .get(id)
                                    .cloned()
                                    .unwrap_or_else(|| serde_json::json!({"ok":true,"lines":[]}))
                            }
                            _ => {
                                serde_json::json!({"ok":false,"error":"unknown method"})
                            }
                        };
                        let mut out = serde_json::to_string(&resp).unwrap();
                        out.push('\n');
                        let _ = wr.write_all(out.as_bytes()).await;
                    }
                });
            }
        });
        sock
    }

    #[tokio::test]
    async fn sync_registers_workloads_and_backfills_logs() {
        let dir = tempfile::tempdir().unwrap();
        let list = serde_json::json!({
            "ok": true,
            "deployments": [
                {"id":"dep-a","app_name":"cloudflared","status":"running","source":"cloudflared tunnel"},
                {"id":"dep-b","app_name":"podman-static","status":"completed","source":"fetch-only"},
            ],
        });
        let mut logs = std::collections::HashMap::new();
        logs.insert(
            "dep-a".into(),
            serde_json::json!({"ok":true,"lines":["cf line 1","cf line 2"]}),
        );
        logs.insert(
            "dep-b".into(),
            serde_json::json!({"ok":true,"lines":["pod fetched"]}),
        );
        let sock = spawn_fake_ee(&dir, list, Arc::new(logs)).await;

        let manager = Manager::new();
        let ee = EeClient::new(&sock);
        sync_once(&manager, &ee).await;

        // Both workloads registered.
        let cf = manager
            .get("cloudflared-dep-a")
            .await
            .expect("cloudflared session registered");
        let pod = manager
            .get("podman-static-dep-b")
            .await
            .expect("podman-static session registered");
        assert_eq!(cf.kind, "workload");
        assert_eq!(pod.kind, "workload");

        // Log lines were fed in (observable via the ring buffer —
        // we don't assert exact bytes, just presence).
        let ring = cf.ring.lock().await;
        let ring_bytes: Vec<u8> = ring.iter().copied().collect();
        let ring_str = String::from_utf8_lossy(&ring_bytes);
        assert!(ring_str.contains("cf line 1"));
        assert!(ring_str.contains("cf line 2"));

        // Terminal status (`completed` on podman-static) committed
        // an exit block.
        let pod_blocks = pod.blocks.read().await;
        assert_eq!(pod_blocks.len(), 1, "podman-static got exit block");
        assert_eq!(pod_blocks[0].exit_code, 0);

        // Non-terminal status (`running` on cloudflared) did not
        // commit an exit block.
        let cf_blocks = cf.blocks.read().await;
        assert_eq!(cf_blocks.len(), 0, "cloudflared still running, no block");
    }
}
