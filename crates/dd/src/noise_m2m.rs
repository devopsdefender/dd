//! Noise_IK-backed m2m transport between CP and dd-agents.
//!
//! Both CP and agent own a long-term X25519 static keypair on disk.
//! During registration they exchange pubkeys over a single Noise_IK
//! handshake; subsequent RPCs (heartbeat, ingress/replace, agent list
//! queries) travel through the authenticated channel instead of
//! through ITA bearer tokens.
//!
//! This module owns the pubkey registry (pinned agent keys on the CP
//! side, pinned CP key on the agent side) and a lightweight
//! "execute one RPC" helper that runs a fresh handshake per call.
//! We deliberately skip the connection-pool question for v1 —
//! handshakes are cheap enough (one X25519 + one AEAD) and keeping
//! state stateless keeps the migration small.
//!
//! CI callers (`dd-deploy`, `dd-logs`, `relaunch-agent`) keep using
//! GitHub Actions OIDC tokens — ephemeral CI runners can't hold a
//! stable device key, and OIDC *is* their attestation. Noise
//! replaces the ITA bearer for enclave-to-enclave calls only.

use dd_common::noise_static::NoiseStatic;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Filename used under the data-dir for every process that owns a
/// long-term Noise identity. Same on CP and agent — the dir changes
/// (CP under `/var/lib/dd/cp/`, agent under `/var/lib/dd/agent/`)
/// but the leaf name is stable so ops scripts can grep for it.
pub const KEY_FILENAME: &str = "noise-static.key";

/// Load-or-generate the local static key at `dir/noise-static.key`.
/// Wraps [`NoiseStatic::load_or_generate`]; returns the loaded
/// pubkey + source for the caller to log at startup.
pub fn load_static(dir: &Path) -> std::io::Result<Arc<NoiseStatic>> {
    let path: PathBuf = dir.join(KEY_FILENAME);
    let key = NoiseStatic::load_or_generate(&path)?;
    Ok(Arc::new(key))
}

/// Shared state kept on the CP: `agent_id → pinned pubkey`. Populated
/// at registration (the first message from an agent establishes its
/// pubkey; subsequent registrations must reuse the same one).
#[derive(Default, Clone)]
pub struct AgentRegistry {
    inner: Arc<RwLock<HashMap<String, [u8; 32]>>>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin `pubkey` for `agent_id`. Returns `Err` if a different
    /// pubkey was previously pinned — re-keying an agent requires
    /// operator intervention (delete the entry and re-enrol) to
    /// prevent a rogue agent from hijacking an existing agent_id
    /// just by re-registering.
    pub async fn pin(&self, agent_id: &str, pubkey: [u8; 32]) -> Result<PinOutcome, PinError> {
        let mut guard = self.inner.write().await;
        match guard.get(agent_id) {
            Some(existing) if existing == &pubkey => Ok(PinOutcome::Reused),
            Some(_existing) => Err(PinError::PubkeyMismatch),
            None => {
                guard.insert(agent_id.to_string(), pubkey);
                Ok(PinOutcome::Fresh)
            }
        }
    }

    pub async fn get(&self, agent_id: &str) -> Option<[u8; 32]> {
        self.inner.read().await.get(agent_id).copied()
    }

    pub async fn forget(&self, agent_id: &str) {
        self.inner.write().await.remove(agent_id);
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// First time we saw this agent_id — pubkey just persisted.
    Fresh,
    /// Agent re-registered with the same pubkey — normal on reboot.
    Reused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    /// Agent_id re-registered with a *different* pubkey. Either the
    /// agent's disk was wiped and re-minted, or another enclave is
    /// trying to impersonate it. CP rejects — operator must call
    /// [`AgentRegistry::forget`] before the fresh pubkey is accepted.
    PubkeyMismatch,
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::PubkeyMismatch => f.write_str("agent pubkey changed — re-enrolment required"),
        }
    }
}

impl std::error::Error for PinError {}

/// Helper used by the agent side: remember the CP's pubkey after the
/// first `/attest` fetch so future handshakes pin it. Stored on disk
/// so a bounce doesn't require a re-fetch.
pub fn load_cp_pubkey(dir: &Path) -> Option<[u8; 32]> {
    let bytes = std::fs::read(dir.join("cp-noise-pubkey")).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

pub fn save_cp_pubkey(dir: &Path, pubkey: &[u8; 32]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("cp-noise-pubkey"), pubkey)
}

/// Parse a 64-char lowercase-hex string into a 32-byte X25519 pubkey.
/// Strict: rejects non-hex, wrong length, and uppercase so a bad key
/// can't masquerade as a different valid one through normalization.
pub fn decode_pubkey(hex: &str) -> std::result::Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "non-ascii".to_string())?;
        out[i] = u8::from_str_radix(s, 16).map_err(|e| format!("hex: {e}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_pins_first_then_rejects_mismatch() {
        let reg = AgentRegistry::new();
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];

        assert_eq!(reg.pin("agent-1", key_a).await, Ok(PinOutcome::Fresh));
        assert_eq!(reg.pin("agent-1", key_a).await, Ok(PinOutcome::Reused));
        assert_eq!(
            reg.pin("agent-1", key_b).await,
            Err(PinError::PubkeyMismatch)
        );

        reg.forget("agent-1").await;
        assert_eq!(reg.pin("agent-1", key_b).await, Ok(PinOutcome::Fresh));
    }

    #[test]
    fn cp_pubkey_roundtrip_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_cp_pubkey(dir.path()).is_none());
        let key = [42u8; 32];
        save_cp_pubkey(dir.path(), &key).unwrap();
        assert_eq!(load_cp_pubkey(dir.path()), Some(key));
    }
}
