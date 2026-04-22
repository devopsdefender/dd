//! Trusted-device pubkey list.
//!
//! Loaded from a JSON file of the shape
//! `{ "pubkeys": ["<32-byte hex>", ...] }`. Polled every
//! [`WATCH_INTERVAL`] for changes so a revoke propagates without a
//! proxy restart. DD's agent writes this file after each heartbeat
//! (see plan Workstream B3).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::RwLock;

const WATCH_INTERVAL: Duration = Duration::from_secs(10);

pub struct TrustStore {
    path: PathBuf,
    inner: RwLock<HashSet<[u8; 32]>>,
}

impl TrustStore {
    pub async fn load_and_watch(path: &Path) -> anyhow::Result<Arc<Self>> {
        let initial = read_file(path).await.unwrap_or_else(|e| {
            eprintln!("ee-proxy: trust file not readable ({e}); starting empty");
            HashSet::new()
        });
        let store = Arc::new(Self {
            path: path.to_path_buf(),
            inner: RwLock::new(initial),
        });

        // Background poller. Treats "file absent" as "empty" — on a
        // fresh enclave the trust file only materializes once the
        // dd-agent's first /api/v1/devices/trusted poll round-trips.
        // Log only on real changes or real errors, not on each
        // absent-file tick.
        {
            let store = store.clone();
            tokio::spawn(async move {
                let mut last_absent = false;
                loop {
                    tokio::time::sleep(WATCH_INTERVAL).await;
                    match read_file(&store.path).await {
                        Ok(fresh) => {
                            last_absent = false;
                            let mut w = store.inner.write().await;
                            if *w != fresh {
                                eprintln!(
                                    "ee-proxy: trust file changed ({} -> {} keys)",
                                    w.len(),
                                    fresh.len()
                                );
                                *w = fresh;
                            }
                        }
                        Err(e) => {
                            let is_missing = e
                                .downcast_ref::<std::io::Error>()
                                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound);
                            if is_missing {
                                // Absent = empty. Log once on transition so
                                // it's obvious from the logs, then stay quiet.
                                if !last_absent {
                                    eprintln!(
                                        "ee-proxy: trust file absent; waiting for dd-agent to populate it"
                                    );
                                    last_absent = true;
                                }
                                let mut w = store.inner.write().await;
                                if !w.is_empty() {
                                    w.clear();
                                }
                            } else {
                                eprintln!("ee-proxy: trust file re-read failed: {e}");
                            }
                        }
                    }
                }
            });
        }

        Ok(store)
    }

    pub async fn contains(&self, pubkey: &[u8; 32]) -> bool {
        self.inner.read().await.contains(pubkey)
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }
}

#[derive(Deserialize)]
struct TrustFile {
    pubkeys: Vec<String>,
}

async fn read_file(path: &Path) -> anyhow::Result<HashSet<[u8; 32]>> {
    let bytes = tokio::fs::read(path).await?;
    let parsed: TrustFile = serde_json::from_slice(&bytes)?;
    let mut out = HashSet::with_capacity(parsed.pubkeys.len());
    for hex_key in parsed.pubkeys {
        let raw = hex::decode(&hex_key)?;
        if raw.len() != 32 {
            anyhow::bail!("trust file: pubkey `{hex_key}` is not 32 bytes");
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        out.insert(k);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn load_and_contains() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        let pk = [7u8; 32];
        let body = serde_json::json!({ "pubkeys": [hex::encode(pk)] });
        tokio::fs::write(&path, body.to_string()).await.unwrap();

        let store = TrustStore::load_and_watch(&path).await.unwrap();
        assert!(store.contains(&pk).await);
        assert!(!store.contains(&[0u8; 32]).await);
    }

    #[tokio::test]
    async fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let store = TrustStore::load_and_watch(&path).await.unwrap();
        assert_eq!(store.len().await, 0);
    }
}
