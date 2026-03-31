pub mod insecure;
pub mod tsm;

use serde_json::Value;

/// Pluggable attestation backend. Each platform (TDX, SEV, TPM, etc.)
/// implements this trait. The agent auto-detects at startup.
pub trait AttestationBackend: Send + Sync {
    /// Platform identifier: "tdx", "sev", "tpm", "insecure", etc.
    fn attestation_type(&self) -> &str;

    /// Generate a base64-encoded attestation quote, if available.
    fn generate_quote_b64(&self) -> Option<String>;

    /// Metadata for the /health endpoint and Noise handshake payload.
    fn health_metadata(&self) -> Value;
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
