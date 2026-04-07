pub mod insecure;
pub mod tsm;

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Pluggable attestation backend. Each platform (TDX, SEV, TPM, etc.)
/// implements this trait. The agent auto-detects at startup.
pub trait AttestationBackend: Send + Sync {
    /// Platform identifier: "tdx", "sev", "tpm", "insecure", etc.
    fn attestation_type(&self) -> &str;

    /// Generate a base64-encoded attestation quote with caller-provided report
    /// data embedded in the quote when supported.
    fn generate_quote_b64_with_report_data(&self, report_data: &[u8]) -> Option<String>;

    /// Generate a base64-encoded attestation quote with empty report data.
    fn generate_quote_b64(&self) -> Option<String> {
        self.generate_quote_b64_with_report_data(&[])
    }

    /// Metadata for the /health endpoint and Noise handshake payload.
    fn health_metadata(&self) -> Value;
}

const NOISE_REPORT_DATA_CONTEXT: &[u8] = b"dd-noise-static-v1";

pub fn noise_static_pubkey_hash(public_key: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(public_key);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn noise_static_pubkey_hash_hex(public_key: &[u8]) -> String {
    noise_static_pubkey_hash(public_key)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn report_data_for_noise_static(public_key: &[u8]) -> [u8; 64] {
    let mut report_data = [0u8; 64];
    let context_len = NOISE_REPORT_DATA_CONTEXT.len();
    report_data[..context_len].copy_from_slice(NOISE_REPORT_DATA_CONTEXT);
    report_data[context_len..context_len + 32]
        .copy_from_slice(&noise_static_pubkey_hash(public_key));
    report_data
}

pub fn verify_quote_binds_noise_static(quote_b64: &str, public_key: &[u8]) -> Result<(), String> {
    let parsed =
        tsm::parse_tdx_quote_base64(quote_b64).map_err(|e| format!("parse TDX quote: {e}"))?;
    let expected = report_data_for_noise_static(public_key);
    if parsed.report_data != expected {
        return Err("TDX report data does not match Noise static key binding".into());
    }
    Ok(())
}

/// Auto-detect the best available attestation backend.
pub fn detect() -> Box<dyn AttestationBackend> {
    // TDX: check for configfs-tsm interface
    if std::path::Path::new("/sys/kernel/config/tsm/report").exists() {
        return Box::new(tsm::TdxBackend);
    }

    // Default: insecure (no hardware attestation)
    Box::new(insecure::InsecureBackend)
}
