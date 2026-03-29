use base64::Engine;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tracing::{info, warn};

const TDX_REPORT_ROOT: &str = "/sys/kernel/config/tsm/report";

/// Generate a TDX attestation quote with the given user data embedded.
/// On non-TDX hosts (dev/CI), returns a deterministic placeholder.
pub fn generate_quote(user_data: &[u8], skip_attestation: bool) -> String {
    if skip_attestation || !is_tdx_available() {
        warn!("TDX not available or skipped, using placeholder quote");
        return placeholder_quote(user_data);
    }

    match generate_tdx_quote(user_data) {
        Ok(quote) => {
            info!("generated TDX attestation quote ({} bytes)", quote.len());
            base64::engine::general_purpose::STANDARD.encode(&quote)
        }
        Err(e) => {
            warn!("TDX quote generation failed: {e}, using placeholder");
            placeholder_quote(user_data)
        }
    }
}

fn is_tdx_available() -> bool {
    Path::new(TDX_REPORT_ROOT).exists()
}

fn generate_tdx_quote(user_data: &[u8]) -> Result<Vec<u8>, String> {
    let report_name = format!("report_{}", uuid::Uuid::new_v4().as_simple());
    let report_dir = format!("{TDX_REPORT_ROOT}/{report_name}");

    fs::create_dir_all(&report_dir).map_err(|e| format!("create report dir: {e}"))?;

    // Pad user data to 64 bytes (configfs-tsm requirement)
    let mut padded = [0u8; 64];
    let copy_len = user_data.len().min(64);
    padded[..copy_len].copy_from_slice(&user_data[..copy_len]);

    // Write user data
    let inblob_path = format!("{report_dir}/inblob");
    fs::write(&inblob_path, padded).map_err(|e| format!("write inblob: {e}"))?;

    // Read generated quote
    let outblob_path = format!("{report_dir}/outblob");
    let quote = fs::read(&outblob_path).map_err(|e| format!("read outblob: {e}"))?;

    // Cleanup
    let _ = fs::remove_dir_all(&report_dir);

    Ok(quote)
}

fn placeholder_quote(user_data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"measurer-dev-mode-");
    hasher.update(user_data);
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}
