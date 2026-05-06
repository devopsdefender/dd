//! TDX attestation + Noise static keypair.
//!
//! On boot we either load an existing 32-byte X25519 private key from
//! disk (tmpfs — `/run/devopsdefender/noise.key`) or mint a fresh one.
//! The corresponding public key is embedded in a TDX quote's
//! `report_data` field (low 32 bytes; high 32 bytes zero). The quote +
//! pubkey bundle is surfaced by the containing service's `/health`
//! endpoint (see `agent::health` and `cp::health`); clients verify
//! the quote via ITA, extract the Noise static pubkey from
//! `report_data`, and trust that key for the handshake. No X.509
//! certs in the loop.
//!
//! There used to be a dedicated `GET /attest` route here. It was
//! collapsed into `/health` so a bastion-app bootstrap does one
//! request instead of two, and so the CF Access bypass list shrinks
//! by one app per env × per service. The Noise quote is stable per
//! boot — just an `Arc<Attestor>` clone on each `/health` hit.

use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct Attestor {
    secret: StaticSecret,
    public: [u8; 32],
    quote: Vec<u8>,
}

impl Attestor {
    /// Load `key_file` if it exists and is 32 bytes, otherwise mint a
    /// fresh keypair and best-effort-persist it with 0600 perms.
    /// Persistence is non-fatal: every deploy already rotates the
    /// enclave Noise key (fresh VM / fresh boot), so losing the write
    /// just means this same VM won't reuse the key across an
    /// in-enclave process restart. Then generate a fresh TDX quote
    /// binding the public key into `report_data`.
    pub async fn load_or_mint(key_file: &Path) -> anyhow::Result<Self> {
        let secret = match tokio::fs::read(key_file).await {
            Ok(bytes) if bytes.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                StaticSecret::from(k)
            }
            _ => {
                let fresh = StaticSecret::random_from_rng(OsRng);
                if let Err(e) = persist_key(key_file, fresh.as_bytes()).await {
                    eprintln!(
                        "noise-gw: persist {} failed ({e}); continuing with in-memory key",
                        key_file.display()
                    );
                }
                fresh
            }
        };

        let public = PublicKey::from(&secret).to_bytes();
        let quote = tdx_quote(&public)?;

        Ok(Self {
            secret,
            public,
            quote,
        })
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }

    pub fn quote(&self) -> &[u8] {
        &self.quote
    }
}

async fn persist_key(key_file: &Path, bytes: &[u8; 32]) -> anyhow::Result<()> {
    if let Some(parent) = key_file.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let tmp: PathBuf = key_file.with_extension("key.tmp");
    tokio::fs::write(&tmp, bytes).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&tmp, perms).await?;
    }
    tokio::fs::rename(&tmp, key_file).await?;
    Ok(())
}

/// Generate a TDX quote over `report_data` derived from the given
/// X25519 pubkey. Drives `configfs-tsm` when available (Linux + TDX
/// kernel); otherwise returns a placeholder and logs a warning. The
/// graceful fallback is what lets `cargo test` and dev runs on
/// non-TDX hosts succeed — the placeholder quote will fail ITA
/// verification, which is exactly what you want off-enclave.
fn tdx_quote(pubkey: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    match try_configfs_tsm_quote(pubkey) {
        Ok(q) => Ok(q),
        Err(e) => {
            eprintln!(
                "noise-gw: configfs-tsm unavailable ({e}); using placeholder quote. \
                 Clients will fail ITA verification — this is expected off-enclave."
            );
            Ok(b"noise-gw-placeholder-quote".to_vec())
        }
    }
}

#[cfg(target_os = "linux")]
fn try_configfs_tsm_quote(pubkey: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    use std::fs;
    use std::io::Write;

    let base = std::path::Path::new("/sys/kernel/config/tsm/report");
    if !base.exists() {
        anyhow::bail!("{} not present", base.display());
    }

    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(pubkey);

    let dir = base.join("devopsdefender");
    fs::create_dir_all(&dir)?;
    {
        let mut inblob = fs::OpenOptions::new()
            .write(true)
            .open(dir.join("inblob"))?;
        inblob.write_all(&report_data)?;
    }
    let outblob = fs::read(dir.join("outblob"))?;
    fs::remove_dir(&dir).ok();
    Ok(outblob)
}

#[cfg(not(target_os = "linux"))]
fn try_configfs_tsm_quote(_pubkey: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    anyhow::bail!("configfs-tsm is Linux-only")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mint_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("noise.key");
        let a = Attestor::load_or_mint(&kf).await.unwrap();
        let pk = *a.public_key();
        let b = Attestor::load_or_mint(&kf).await.unwrap();
        assert_eq!(&pk, b.public_key());
    }
}
