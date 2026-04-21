//! Noise handshake groundwork (Phase 2a — scaffolding only).
//!
//! This module owns bastion's long-term Noise static keypair. The
//! keypair is generated once on first boot and persisted so
//! subsequent boots (or restarts within the same VM) reuse the same
//! pubkey. Clients that have already pinned the pubkey after an
//! attested handshake (Phase 2d) won't see it rotate without
//! reason.
//!
//! Phase 2b will add the actual Noise_KK handshake + encrypted
//! `/api/sessions` and `/ws/*` channels; Phase 2d binds the pubkey
//! into the TDX quote's `REPORT_DATA` so clients can verify the
//! keypair came from a genuine attested enclave. Today we just
//! expose the pubkey via `GET /attest` so client code can start
//! caching it.

use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// 32-byte Noise static key material persisted on disk. Passed to
/// [`Manager::with_noise_key`](crate::Manager::with_noise_key) so
/// HTTP handlers can expose the pubkey.
pub struct NoiseStatic {
    #[allow(dead_code)] // Phase 2b consumes this for the handshake
    secret: StaticSecret,
    public: PublicKey,
    source: NoiseKeySource,
}

impl std::fmt::Debug for NoiseStatic {
    /// Never print the secret half. `{:?}` shows only the pubkey
    /// (truncated) + the source so an accidental log line doesn't
    /// leak the long-term identity.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = self.public_hex();
        let short = &hex[..hex.len().min(16)];
        write!(f, "NoiseStatic({:?}, {}…)", self.source, short)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum NoiseKeySource {
    /// Fresh random key, written to disk for the first time.
    Generated,
    /// Loaded from an existing on-disk key file.
    Loaded,
}

impl NoiseStatic {
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Hex-encoded pubkey for JSON wire use.
    pub fn public_hex(&self) -> String {
        hex::encode(self.public.as_bytes())
    }

    pub fn source(&self) -> NoiseKeySource {
        self.source
    }

    /// Ephemeral in-memory keypair. Used for tests and for the
    /// standalone `bastion serve` local-dev binary where persistence
    /// isn't meaningful across restarts.
    pub fn ephemeral() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public,
            source: NoiseKeySource::Generated,
        }
    }

    /// Load an existing static key from `path`, or mint a fresh one
    /// and write it if the file doesn't exist. Always `chmod 0600`
    /// after write — the file is the enclave's long-term identity;
    /// only bastion should read it.
    pub fn load_or_generate(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path: PathBuf = path.as_ref().to_path_buf();
        if path.exists() {
            let bytes = std::fs::read(&path)?;
            if bytes.len() != 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "noise key file {} is {} bytes; expected 32",
                        path.display(),
                        bytes.len()
                    ),
                ));
            }
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&bytes);
            let secret = StaticSecret::from(sk);
            let public = PublicKey::from(&secret);
            return Ok(Self {
                secret,
                public,
                source: NoiseKeySource::Loaded,
            });
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let s = Self::ephemeral();
        let bytes: [u8; 32] = s.secret.to_bytes();
        std::fs::write(&path, bytes)?;
        chmod_0600(&path)?;
        Ok(Self {
            secret: s.secret,
            public: s.public,
            source: NoiseKeySource::Generated,
        })
    }
}

fn chmod_0600(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
}

// `hex` is pulled in transitively via existing deps; if the
// transitive path changes, add `hex = "0.4"` to `Cargo.toml`
// explicitly.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_is_random_each_call() {
        let a = NoiseStatic::ephemeral();
        let b = NoiseStatic::ephemeral();
        assert_ne!(a.public().as_bytes(), b.public().as_bytes());
        assert_eq!(a.public_hex().len(), 64);
    }

    #[test]
    fn load_or_generate_is_stable_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("noise-static.key");
        let first = NoiseStatic::load_or_generate(&path).unwrap();
        let second = NoiseStatic::load_or_generate(&path).unwrap();
        assert_eq!(first.public().as_bytes(), second.public().as_bytes());
        assert!(matches!(first.source(), NoiseKeySource::Generated));
        assert!(matches!(second.source(), NoiseKeySource::Loaded));
    }

    #[test]
    fn load_or_generate_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.key");
        std::fs::write(&path, b"too short").unwrap();
        let err = NoiseStatic::load_or_generate(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn key_file_is_chmod_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("noise-static.key");
        let _ = NoiseStatic::load_or_generate(&path).unwrap();
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
