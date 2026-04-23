//! TDX attestation + Noise static keypair.
//!
//! On boot we either load an existing 32-byte X25519 private key from
//! disk (tmpfs — `/run/devopsdefender/noise.key`) or mint a fresh one.
//! The corresponding public key is embedded in a TDX quote's
//! `report_data` field (low 32 bytes; high 32 bytes zero). Clients
//! fetch `GET /attest` over plain HTTPS, verify the quote via ITA,
//! extract the Noise static pubkey from `report_data`, and trust
//! that key for the handshake. No X.509 certs in the loop.
//!
//! When `DD_ITA_*` is configured, we also mint an ITA-signed JWT
//! over the same quote at boot and refresh it in the background.
//! The JWT rides in `/attest` as `ita_token`; a client that checks
//! it escapes TOFU-pin semantics entirely. Mint failures are
//! non-fatal — the field is simply omitted and clients fall back
//! to TOFU.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::rngs::OsRng;
use serde::Serialize;
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::Ita;

/// How often we re-mint the `/attest` ITA token. The token itself
/// is valid for ~24h from Intel, but the Noise quote is immutable
/// for the life of the process, so re-minting is cheap insurance
/// against JWKS-rotation edge cases.
const ITA_REFRESH: Duration = Duration::from_secs(3600);

pub struct Attestor {
    secret: StaticSecret,
    public: [u8; 32],
    quote: Vec<u8>,
    /// ITA-minted JWT over `quote`. `None` until `start_ita_refresh`
    /// successfully mints once (and cleared on repeated failure is
    /// avoided — we keep the last good token so a brief Intel outage
    /// doesn't drop clients into TOFU).
    ita_token: Arc<RwLock<Option<String>>>,
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
            ita_token: Arc::new(RwLock::new(None)),
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

    /// Mint an initial ITA token and spawn a background task that
    /// re-mints every [`ITA_REFRESH`]. Non-fatal on failure: the
    /// token field stays `None` and `/attest` omits it, which puts
    /// the client back on TOFU semantics rather than refusing the
    /// handshake.
    ///
    /// Off-enclave (placeholder quote), the mint will 4xx — we log
    /// and move on. In prod the quote is real and the mint should
    /// succeed on every refresh.
    pub fn start_ita_refresh(self: &Arc<Self>, ita: Ita) {
        let me = self.clone();
        tokio::spawn(async move {
            match me.mint_once(&ita).await {
                Ok(tok) => {
                    eprintln!(
                        "noise-gw: minted initial /attest ITA token ({} bytes)",
                        tok.len()
                    );
                    *me.ita_token.write().await = Some(tok);
                }
                Err(e) => eprintln!("noise-gw: initial /attest ITA mint failed: {e}"),
            }
            loop {
                tokio::time::sleep(ITA_REFRESH).await;
                match me.mint_once(&ita).await {
                    Ok(tok) => *me.ita_token.write().await = Some(tok),
                    Err(e) => eprintln!("noise-gw: /attest ITA refresh failed: {e}"),
                }
            }
        });
    }

    async fn mint_once(&self, ita: &Ita) -> crate::error::Result<String> {
        let quote_b64 = B64.encode(&self.quote);
        crate::ita::mint(&ita.base_url, &ita.api_key, &quote_b64).await
    }

    pub async fn ita_token(&self) -> Option<String> {
        self.ita_token.read().await.clone()
    }
}

pub(crate) fn routes() -> Router<super::State> {
    Router::new().route("/attest", get(attest))
}

#[derive(Serialize)]
struct AttestResponse {
    quote_b64: String,
    pubkey_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ita_token: Option<String>,
}

async fn attest(State(s): State<super::State>) -> Json<AttestResponse> {
    Json(AttestResponse {
        quote_b64: B64.encode(s.attest.quote()),
        pubkey_hex: hex::encode(s.attest.public_key()),
        ita_token: s.attest.ita_token().await,
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

    #[tokio::test]
    async fn ita_token_default_none_and_updatable() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("noise.key");
        let a = Arc::new(Attestor::load_or_mint(&kf).await.unwrap());
        assert!(a.ita_token().await.is_none());
        *a.ita_token.write().await = Some("stub.jwt".into());
        assert_eq!(a.ita_token().await.as_deref(), Some("stub.jwt"));
    }
}
