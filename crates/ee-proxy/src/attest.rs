//! TDX attestation + Noise static keypair.
//!
//! On boot we either load an existing 32-byte X25519 private key from
//! disk (tmpfs — `/run/ee-proxy/noise.key`) or mint a fresh one. The
//! corresponding public key is embedded in a TDX quote's
//! `report_data` field (low 32 bytes; high 32 bytes zero).
//!
//! Clients fetch `GET /attest` over plain HTTPS, verify the quote via
//! ITA, extract the Noise static pubkey from `report_data`, and trust
//! that key for the handshake. No X.509 certs in the loop.

use std::path::{Path, PathBuf};

use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::rngs::OsRng;
use serde::Serialize;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct Attestor {
    secret: StaticSecret,
    public: [u8; 32],
    quote: Vec<u8>,
}

impl Attestor {
    /// Load `key_file` if it exists and is 32 bytes, otherwise mint a
    /// fresh keypair and persist it with 0600 perms. Then generate a
    /// fresh TDX quote binding the public key into `report_data`.
    pub async fn load_or_mint(key_file: &Path) -> anyhow::Result<Self> {
        let secret = match tokio::fs::read(key_file).await {
            Ok(bytes) if bytes.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                StaticSecret::from(k)
            }
            _ => {
                let fresh = StaticSecret::random_from_rng(OsRng);
                persist_key(key_file, fresh.as_bytes()).await?;
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

pub(crate) fn routes() -> Router<crate::State> {
    Router::new().route("/attest", get(attest))
}

#[derive(Serialize)]
struct AttestResponse {
    quote_b64: String,
    pubkey_hex: String,
}

async fn attest(State(s): State<crate::State>) -> Json<AttestResponse> {
    Json(AttestResponse {
        quote_b64: B64.encode(s.attest.quote()),
        pubkey_hex: hex::encode(s.attest.public_key()),
    })
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
/// X25519 pubkey. On Linux this drives `configfs-tsm`; elsewhere we
/// return an error (the proxy is only deployed in Linux enclaves).
#[cfg(target_os = "linux")]
fn tdx_quote(pubkey: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    use std::fs;
    use std::io::Write;

    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(pubkey);

    let dir = "/sys/kernel/config/tsm/report/ee-proxy";
    fs::create_dir_all(dir)?;
    {
        let mut inblob = fs::OpenOptions::new()
            .write(true)
            .open(format!("{dir}/inblob"))?;
        inblob.write_all(&report_data)?;
    }
    let outblob = fs::read(format!("{dir}/outblob"))?;
    fs::remove_dir(dir).ok();
    Ok(outblob)
}

#[cfg(not(target_os = "linux"))]
fn tdx_quote(_pubkey: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    // Non-Linux build — used for `cargo check` on dev machines.
    // Return a placeholder so constructors still succeed; the binary
    // only actually runs inside a TDX VM.
    Ok(b"non-linux-placeholder-quote".to_vec())
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
        // Second load should yield the same pubkey.
        let b = Attestor::load_or_mint(&kf).await.unwrap();
        assert_eq!(&pk, b.public_key());
    }
}
