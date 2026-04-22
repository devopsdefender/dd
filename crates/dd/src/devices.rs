//! Device pubkey registry.
//!
//! Holds the X25519 pubkeys of paired client devices. Source of truth
//! lives on the CP's disk at [`Store::path`] (JSON, pretty-printed for
//! human editability in a pinch). A runtime view at
//! [`RUNTIME_TRUST_PATH`] (tmpfs) is re-written on every mutation so
//! the locally-running `ee-proxy` workload picks up the current
//! allowlist without an HTTP round-trip.
//!
//! Wire format on disk:
//! ```json
//! {
//!   "devices": [
//!     { "pubkey": "<64-hex>", "label": "alice@laptop",
//!       "created_at_ms": 1734567890000, "revoked_at_ms": null }
//!   ]
//! }
//! ```
//!
//! Runtime (ee-proxy) view — only non-revoked pubkeys:
//! ```json
//! { "pubkeys": ["<64-hex>", "<64-hex>"] }
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Where the local `ee-proxy` workload expects to read its trust
/// list. Must match `ee-proxy`'s `--trust-file` default.
pub const RUNTIME_TRUST_PATH: &str = "/run/ee-proxy/trusted-devices.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub pubkey: String,
    pub label: String,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_ms: Option<i64>,
}

#[derive(Default, Serialize, Deserialize)]
struct OnDisk {
    #[serde(default)]
    devices: Vec<Device>,
}

#[derive(Serialize)]
struct RuntimeView<'a> {
    pubkeys: Vec<&'a str>,
}

pub struct Store {
    path: PathBuf,
    runtime_path: PathBuf,
    inner: RwLock<BTreeMap<String, Device>>,
}

impl Store {
    /// Load the source-of-truth file (missing is fine — starts empty)
    /// and emit the runtime view so the local ee-proxy sees the
    /// current set immediately after CP boot.
    pub async fn load(path: PathBuf, runtime_path: PathBuf) -> anyhow::Result<Arc<Self>> {
        let devices = match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed: OnDisk = serde_json::from_slice(&bytes)?;
                parsed.devices
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        let map: BTreeMap<_, _> = devices.into_iter().map(|d| (d.pubkey.clone(), d)).collect();
        let store = Arc::new(Self {
            path,
            runtime_path,
            inner: RwLock::new(map),
        });
        store.flush_runtime().await?;
        Ok(store)
    }

    pub async fn list(&self) -> Vec<Device> {
        self.inner.read().await.values().cloned().collect()
    }

    pub async fn upsert(&self, device: Device) -> anyhow::Result<()> {
        {
            let mut w = self.inner.write().await;
            w.insert(device.pubkey.clone(), device);
        }
        self.flush_source().await?;
        self.flush_runtime().await?;
        Ok(())
    }

    /// Marks `pubkey` as revoked at `now_ms`. Returns `true` if the
    /// record existed and wasn't already revoked.
    pub async fn revoke(&self, pubkey: &str, now_ms: i64) -> anyhow::Result<bool> {
        let ok = {
            let mut w = self.inner.write().await;
            match w.get_mut(pubkey) {
                Some(d) if d.revoked_at_ms.is_none() => {
                    d.revoked_at_ms = Some(now_ms);
                    true
                }
                _ => false,
            }
        };
        if ok {
            self.flush_source().await?;
            self.flush_runtime().await?;
        }
        Ok(ok)
    }

    async fn flush_source(&self) -> anyhow::Result<()> {
        let devices: Vec<Device> = self.inner.read().await.values().cloned().collect();
        let on_disk = OnDisk { devices };
        let bytes = serde_json::to_vec_pretty(&on_disk)?;
        atomic_write(&self.path, &bytes).await
    }

    async fn flush_runtime(&self) -> anyhow::Result<()> {
        let guard = self.inner.read().await;
        let pubkeys: Vec<&str> = guard
            .values()
            .filter(|d| d.revoked_at_ms.is_none())
            .map(|d| d.pubkey.as_str())
            .collect();
        let view = RuntimeView { pubkeys };
        let bytes = serde_json::to_vec(&view)?;
        atomic_write(&self.runtime_path, &bytes).await
    }
}

async fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// Validate a hex pubkey: exactly 64 chars of lowercase or uppercase
/// hex, decoding to 32 bytes.
pub fn validate_hex_pubkey(s: &str) -> anyhow::Result<()> {
    if s.len() != 64 {
        anyhow::bail!("pubkey must be 64 hex chars (got {})", s.len());
    }
    let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("not valid hex: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("pubkey must decode to 32 bytes (got {})", bytes.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_dev(pk: &str, label: &str) -> Device {
        Device {
            pubkey: pk.into(),
            label: label.into(),
            created_at_ms: 1,
            revoked_at_ms: None,
        }
    }

    #[tokio::test]
    async fn upsert_persists_and_exports_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("devices.json");
        let run = dir.path().join("runtime/trusted.json");
        let store = Store::load(src.clone(), run.clone()).await.unwrap();

        let pk1 = "a".repeat(64);
        let pk2 = "b".repeat(64);
        store.upsert(mk_dev(&pk1, "laptop")).await.unwrap();
        store.upsert(mk_dev(&pk2, "phone")).await.unwrap();

        // Source of truth has both.
        let src_bytes = tokio::fs::read(&src).await.unwrap();
        let src_val: serde_json::Value = serde_json::from_slice(&src_bytes).unwrap();
        assert_eq!(src_val["devices"].as_array().unwrap().len(), 2);

        // Runtime view has both pubkeys, no metadata.
        let run_bytes = tokio::fs::read(&run).await.unwrap();
        let run_val: serde_json::Value = serde_json::from_slice(&run_bytes).unwrap();
        let runtime_keys: Vec<_> = run_val["pubkeys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(runtime_keys.contains(&pk1));
        assert!(runtime_keys.contains(&pk2));
    }

    #[tokio::test]
    async fn revoke_drops_from_runtime_but_keeps_source() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("devices.json");
        let run = dir.path().join("trusted.json");
        let store = Store::load(src.clone(), run.clone()).await.unwrap();

        let pk = "c".repeat(64);
        store.upsert(mk_dev(&pk, "laptop")).await.unwrap();
        let ok = store.revoke(&pk, 99).await.unwrap();
        assert!(ok);

        // Revoking again is a no-op.
        assert!(!store.revoke(&pk, 100).await.unwrap());

        // Source file still has the record with a revoked_at_ms stamp.
        let src_bytes = tokio::fs::read(&src).await.unwrap();
        let src_val: serde_json::Value = serde_json::from_slice(&src_bytes).unwrap();
        let d = &src_val["devices"][0];
        assert_eq!(d["pubkey"].as_str().unwrap(), pk);
        assert_eq!(d["revoked_at_ms"].as_i64(), Some(99));

        // Runtime view no longer lists it.
        let run_bytes = tokio::fs::read(&run).await.unwrap();
        let run_val: serde_json::Value = serde_json::from_slice(&run_bytes).unwrap();
        assert!(run_val["pubkeys"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn load_persists_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("devices.json");
        let run = dir.path().join("trusted.json");
        let pk = "e".repeat(64);
        {
            let s = Store::load(src.clone(), run.clone()).await.unwrap();
            s.upsert(mk_dev(&pk, "desktop")).await.unwrap();
        }
        let s2 = Store::load(src.clone(), run.clone()).await.unwrap();
        let list = s2.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].pubkey, pk);
    }

    #[test]
    fn validate_hex_pubkey_happy_and_sad() {
        validate_hex_pubkey(&"0".repeat(64)).unwrap();
        validate_hex_pubkey(&"F".repeat(64)).unwrap();
        assert!(validate_hex_pubkey("").is_err());
        assert!(validate_hex_pubkey(&"0".repeat(63)).is_err());
        assert!(validate_hex_pubkey(&"g".repeat(64)).is_err());
    }
}
