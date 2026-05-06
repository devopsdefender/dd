//! Device pubkey registry.
//!
//! Holds the X25519 pubkeys of paired client devices. Source of truth
//! lives on the CP's disk at [`Store::path`] (JSON, pretty-printed for
//! human editability in a pinch). The live set of *non-revoked*
//! pubkeys is also mirrored into a [`noise_gateway::TrustHandle`] so
//! the locally-running Noise gateway can read it directly from shared
//! memory — no on-disk runtime view, no cross-process file contract.
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

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::noise_gateway::TrustHandle;

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

pub struct Store {
    path: PathBuf,
    inner: RwLock<BTreeMap<String, Device>>,
    trust: TrustHandle,
}

impl Store {
    /// Load the source-of-truth file (missing is fine — starts empty)
    /// and seed the shared `TrustHandle` with the current non-revoked
    /// set. Every mutation after this recomputes the handle in place.
    pub async fn load(path: PathBuf, trust: TrustHandle) -> anyhow::Result<Arc<Self>> {
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
            inner: RwLock::new(map),
            trust,
        });
        store.sync_trust_handle().await;
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
        self.sync_trust_handle().await;
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
            self.sync_trust_handle().await;
        }
        Ok(ok)
    }

    /// Full snapshot — including revoked records — for `/api/v1/admin/export`.
    pub async fn export_full(&self) -> Vec<Device> {
        self.list().await
    }

    /// Merge a batch of device records into the store. Each pubkey
    /// overwrites any existing record (later `revoked_at_ms` wins via
    /// plain overwrite since callers always hand us the latest).
    /// Persists to disk + refreshes the trust handle.
    pub async fn import_merge(&self, devices: Vec<Device>) -> anyhow::Result<usize> {
        let mut n = 0;
        {
            let mut w = self.inner.write().await;
            for d in devices {
                w.insert(d.pubkey.clone(), d);
                n += 1;
            }
        }
        self.flush_source().await?;
        self.sync_trust_handle().await;
        Ok(n)
    }

    async fn flush_source(&self) -> anyhow::Result<()> {
        let devices: Vec<Device> = self.inner.read().await.values().cloned().collect();
        let on_disk = OnDisk { devices };
        let bytes = serde_json::to_vec_pretty(&on_disk)?;
        atomic_write(&self.path, &bytes).await
    }

    async fn sync_trust_handle(&self) {
        let guard = self.inner.read().await;
        let mut fresh: HashSet<[u8; 32]> = HashSet::with_capacity(guard.len());
        for d in guard.values() {
            if d.revoked_at_ms.is_some() {
                continue;
            }
            if let Ok(bytes) = hex::decode(&d.pubkey) {
                if bytes.len() == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&bytes);
                    fresh.insert(k);
                }
            }
        }
        *self.trust.write().await = fresh;
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
    use crate::noise_gateway;

    fn mk_dev(pk: &str, label: &str) -> Device {
        Device {
            pubkey: pk.into(),
            label: label.into(),
            created_at_ms: 1,
            revoked_at_ms: None,
        }
    }

    fn pk_bytes(hex_str: &str) -> [u8; 32] {
        let v = hex::decode(hex_str).unwrap();
        let mut k = [0u8; 32];
        k.copy_from_slice(&v);
        k
    }

    #[tokio::test]
    async fn upsert_persists_and_mirrors_trust_handle() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("devices.json");
        let trust = noise_gateway::new_trust_handle();
        let store = Store::load(src.clone(), trust.clone()).await.unwrap();

        let pk1 = "a".repeat(64);
        let pk2 = "b".repeat(64);
        store.upsert(mk_dev(&pk1, "laptop")).await.unwrap();
        store.upsert(mk_dev(&pk2, "phone")).await.unwrap();

        // Source has both records.
        let src_val: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&src).await.unwrap()).unwrap();
        assert_eq!(src_val["devices"].as_array().unwrap().len(), 2);

        // Trust handle reflects both pubkeys.
        let live = trust.read().await;
        assert!(live.contains(&pk_bytes(&pk1)));
        assert!(live.contains(&pk_bytes(&pk2)));
        assert_eq!(live.len(), 2);
    }

    #[tokio::test]
    async fn revoke_drops_from_trust_handle_but_keeps_source() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("devices.json");
        let trust = noise_gateway::new_trust_handle();
        let store = Store::load(src.clone(), trust.clone()).await.unwrap();

        let pk = "c".repeat(64);
        store.upsert(mk_dev(&pk, "laptop")).await.unwrap();
        assert!(store.revoke(&pk, 99).await.unwrap());
        assert!(!store.revoke(&pk, 100).await.unwrap());

        let src_val: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&src).await.unwrap()).unwrap();
        assert_eq!(src_val["devices"][0]["revoked_at_ms"].as_i64(), Some(99));

        assert!(trust.read().await.is_empty());
    }

    #[tokio::test]
    async fn load_persists_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("devices.json");
        let pk = "e".repeat(64);
        {
            let trust = noise_gateway::new_trust_handle();
            let s = Store::load(src.clone(), trust).await.unwrap();
            s.upsert(mk_dev(&pk, "desktop")).await.unwrap();
        }
        let trust2 = noise_gateway::new_trust_handle();
        let s2 = Store::load(src.clone(), trust2.clone()).await.unwrap();
        let list = s2.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].pubkey, pk);
        assert!(trust2.read().await.contains(&pk_bytes(&pk)));
    }

    #[tokio::test]
    async fn import_merge_roundtrips_with_export() {
        let dir = tempfile::tempdir().unwrap();
        let src_a = dir.path().join("a.json");
        let src_b = dir.path().join("b.json");
        let trust_a = noise_gateway::new_trust_handle();
        let trust_b = noise_gateway::new_trust_handle();
        let a = Store::load(src_a, trust_a).await.unwrap();
        let b = Store::load(src_b, trust_b.clone()).await.unwrap();

        let pk_live = "1".repeat(64);
        let pk_revoked = "2".repeat(64);
        a.upsert(mk_dev(&pk_live, "live")).await.unwrap();
        a.upsert(mk_dev(&pk_revoked, "gone")).await.unwrap();
        a.revoke(&pk_revoked, 42).await.unwrap();

        let exported = a.export_full().await;
        let merged = b.import_merge(exported).await.unwrap();
        assert_eq!(merged, 2);

        let list_b = b.list().await;
        assert_eq!(list_b.len(), 2);
        // Only the non-revoked pubkey is in B's trust handle.
        let trust = trust_b.read().await;
        assert_eq!(trust.len(), 1);
        assert!(trust.contains(&pk_bytes(&pk_live)));
        assert!(!trust.contains(&pk_bytes(&pk_revoked)));
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
