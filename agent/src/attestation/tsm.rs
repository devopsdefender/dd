//! TDX quote generation and parsing via Linux configfs-tsm.
//!
//! Layout constants target the TDX v4 quote format where the TD report body
//! begins at byte 48 (immediately after the 48-byte header).

use crate::common::error::{AppError, AppResult};

// ── TDX v4 quote layout constants ──────────────────────────────────────────

/// Size of the quote header (bytes).
pub const QUOTE_HEADER_SIZE: usize = 48;

/// Size of the TD report body (bytes).
pub const TD_REPORT_SIZE: usize = 584;

/// Minimum number of bytes required for a valid TDX v4 quote.
pub const MIN_QUOTE_SIZE: usize = QUOTE_HEADER_SIZE + TD_REPORT_SIZE; // 632

// Offsets are relative to the start of the TD report body.
const MRTD_OFFSET: usize = 136;
const MRTD_LEN: usize = 48;

const RTMR0_OFFSET: usize = 328;
const RTMR1_OFFSET: usize = 376;
const RTMR2_OFFSET: usize = 424;
const RTMR3_OFFSET: usize = 472;
const RTMR_LEN: usize = 48;

const REPORT_DATA_OFFSET: usize = 520;
const REPORT_DATA_LEN: usize = 64;

// ── Parsed representation ──────────────────────────────────────────────────

/// Parsed subset of a TDX v4 quote carrying the fields we care about.
#[derive(Debug, Clone)]
pub struct ParsedQuote {
    /// Quote header version field (first two bytes, little-endian).
    pub version: u16,
    /// Total size of the raw quote in bytes.
    pub quote_size: usize,
    /// MRTD (measurement of initial contents and configuration of the TD).
    pub mrtd: [u8; 48],
    /// Runtime measurement registers 0-3.
    pub rtmrs: [[u8; 48]; 4],
    /// 64-byte report data embedded in the quote.
    pub report_data: [u8; 64],
}

impl ParsedQuote {
    /// MRTD as a lowercase hex string.
    pub fn mrtd_hex(&self) -> String {
        hex(&self.mrtd)
    }

    /// RTMR at `index` (0..=3) as a lowercase hex string.
    ///
    /// # Panics
    /// Panics when `index > 3`.
    pub fn rtmr_hex(&self, index: usize) -> String {
        hex(&self.rtmrs[index])
    }

    /// Report data as a lowercase hex string.
    pub fn report_data_hex(&self) -> String {
        hex(&self.report_data)
    }
}

// ── Parsing helpers ────────────────────────────────────────────────────────

/// Parse a raw TDX v4 quote from bytes.
pub fn parse_tdx_quote(bytes: &[u8]) -> AppResult<ParsedQuote> {
    if bytes.len() < MIN_QUOTE_SIZE {
        return Err(AppError::InvalidInput(format!(
            "TDX quote too short: {} bytes (need at least {})",
            bytes.len(),
            MIN_QUOTE_SIZE
        )));
    }

    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    let body = &bytes[QUOTE_HEADER_SIZE..];

    let mrtd = copy_fixed_48(&body[MRTD_OFFSET..MRTD_OFFSET + MRTD_LEN]);
    let rtmr0 = copy_fixed_48(&body[RTMR0_OFFSET..RTMR0_OFFSET + RTMR_LEN]);
    let rtmr1 = copy_fixed_48(&body[RTMR1_OFFSET..RTMR1_OFFSET + RTMR_LEN]);
    let rtmr2 = copy_fixed_48(&body[RTMR2_OFFSET..RTMR2_OFFSET + RTMR_LEN]);
    let rtmr3 = copy_fixed_48(&body[RTMR3_OFFSET..RTMR3_OFFSET + RTMR_LEN]);
    let report_data =
        copy_fixed_64(&body[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_LEN]);

    Ok(ParsedQuote {
        version,
        quote_size: bytes.len(),
        mrtd,
        rtmrs: [rtmr0, rtmr1, rtmr2, rtmr3],
        report_data,
    })
}

/// Parse a base64-encoded TDX quote.
pub fn parse_tdx_quote_base64(b64_str: &str) -> AppResult<ParsedQuote> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64_str)
        .map_err(|e| AppError::InvalidInput(format!("invalid base64: {e}")))?;
    parse_tdx_quote(&bytes)
}

/// Extract the MRTD hex string from raw quote bytes.
pub fn extract_mrtd_hex(bytes: &[u8]) -> AppResult<String> {
    parse_tdx_quote(bytes).map(|q| q.mrtd_hex())
}

/// Extract a specific RTMR hex string from raw quote bytes.
pub fn extract_rtmr_hex(bytes: &[u8], index: usize) -> AppResult<String> {
    if index > 3 {
        return Err(AppError::InvalidInput(format!(
            "RTMR index must be 0..=3, got {index}"
        )));
    }
    parse_tdx_quote(bytes).map(|q| q.rtmr_hex(index))
}

/// Extract report data hex string from raw quote bytes.
pub fn extract_report_data_hex(bytes: &[u8]) -> AppResult<String> {
    parse_tdx_quote(bytes).map(|q| q.report_data_hex())
}

/// Check whether the report data in a parsed quote starts with the given nonce hex.
pub fn report_data_starts_with_nonce_hex(quote: &ParsedQuote, nonce_hex: &str) -> bool {
    let rd_hex = quote.report_data_hex();
    rd_hex.starts_with(nonce_hex)
}

// ── Quote generation (configfs-tsm) ────────────────────────────────────────

/// Generate a TDX quote by writing user data to the configfs-tsm report
/// interface and reading back the binary quote.
///
/// `report_root` – path to the tsm report entry, e.g. `/sys/kernel/config/tsm/report/report0`.
/// `user_data`   – up to 64 bytes that will be embedded as report data.
pub fn generate_tdx_quote(report_root: &str, user_data: &[u8]) -> AppResult<Vec<u8>> {
    use std::fs;
    use std::path::Path;

    let root = Path::new(report_root);

    // Pad or truncate user data to exactly 64 bytes (configfs-tsm requirement).
    let mut padded = [0u8; 64];
    let copy_len = user_data.len().min(64);
    padded[..copy_len].copy_from_slice(&user_data[..copy_len]);

    // Write raw binary user data to the inblob file.
    let inblob_path = root.join("inblob");
    fs::write(&inblob_path, padded)
        .map_err(|e| AppError::External(format!("write inblob: {e}")))?;

    // Read the generated binary quote.
    let outblob_path = root.join("outblob");
    let quote_bytes =
        fs::read(&outblob_path).map_err(|e| AppError::External(format!("read outblob: {e}")))?;

    Ok(quote_bytes)
}

/// Generate a TDX quote and return it as a base64-encoded string.
///
/// Uses the default configfs-tsm report path.
pub fn generate_tdx_quote_base64_with_user_data(user_data: &[u8]) -> AppResult<String> {
    use base64::Engine;

    // Create a unique report entry under configfs-tsm.
    let report_name = format!("report_{}", uuid::Uuid::new_v4().as_simple());
    let report_root = format!("/sys/kernel/config/tsm/report/{report_name}");

    // Attempt to create the report directory.
    std::fs::create_dir_all(&report_root)
        .map_err(|e| AppError::External(format!("create tsm report dir: {e}")))?;

    let quote_bytes = generate_tdx_quote(&report_root, user_data)?;

    // Clean up.
    let _ = std::fs::remove_dir_all(&report_root);

    Ok(base64::engine::general_purpose::STANDARD.encode(&quote_bytes))
}

pub fn generate_tdx_quote_base64() -> AppResult<String> {
    generate_tdx_quote_base64_with_user_data(&[])
}

// ── Utility functions ──────────────────────────────────────────────────────

/// Convert a byte slice to a lowercase hex string.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn copy_fixed_48(src: &[u8]) -> [u8; 48] {
    let mut dst = [0u8; 48];
    dst.copy_from_slice(&src[..48]);
    dst
}

fn copy_fixed_64(src: &[u8]) -> [u8; 64] {
    let mut dst = [0u8; 64];
    dst.copy_from_slice(&src[..64]);
    dst
}

// ── AttestationBackend implementation ──────────────────────────────────────

/// TDX attestation backend using configfs-tsm.
pub struct TdxBackend;

impl super::AttestationBackend for TdxBackend {
    fn attestation_type(&self) -> &str {
        "tdx"
    }

    fn generate_quote_b64_with_report_data(&self, report_data: &[u8]) -> Option<String> {
        generate_tdx_quote_base64_with_user_data(report_data).ok()
    }

    fn health_metadata(&self) -> serde_json::Value {
        let quote = self.generate_quote_b64();
        let parsed: Option<ParsedQuote> =
            quote.as_ref().and_then(|q| parse_tdx_quote_base64(q).ok());

        let mrtd = parsed.as_ref().map(|p| p.mrtd_hex());
        let rtmr0 = parsed.as_ref().map(|p| hex(&p.rtmrs[0]));
        let rtmr1 = parsed.as_ref().map(|p| hex(&p.rtmrs[1]));

        serde_json::json!({
            "attestation_type": "tdx",
            "mrtd": mrtd,
            "rtmr0": rtmr0,
            "rtmr1": rtmr1,
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// Build a fake TDX v4 quote with known sentinel bytes at the expected
    /// offsets so we can verify the parser pulls them out correctly.
    fn build_fake_quote() -> Vec<u8> {
        build_fake_quote_with_report_data(None)
    }

    fn build_fake_quote_with_report_data(report_data: Option<[u8; 64]>) -> Vec<u8> {
        let mut buf = vec![0u8; MIN_QUOTE_SIZE + 64]; // a bit larger than minimum

        // Version = 4 (little-endian).
        buf[0] = 4;
        buf[1] = 0;

        let body = QUOTE_HEADER_SIZE;

        // MRTD: fill with 0xAA.
        for b in &mut buf[body + MRTD_OFFSET..body + MRTD_OFFSET + MRTD_LEN] {
            *b = 0xAA;
        }

        // RTMR0: 0x10, RTMR1: 0x20, RTMR2: 0x30, RTMR3: 0x40.
        for b in &mut buf[body + RTMR0_OFFSET..body + RTMR0_OFFSET + RTMR_LEN] {
            *b = 0x10;
        }
        for b in &mut buf[body + RTMR1_OFFSET..body + RTMR1_OFFSET + RTMR_LEN] {
            *b = 0x20;
        }
        for b in &mut buf[body + RTMR2_OFFSET..body + RTMR2_OFFSET + RTMR_LEN] {
            *b = 0x30;
        }
        for b in &mut buf[body + RTMR3_OFFSET..body + RTMR3_OFFSET + RTMR_LEN] {
            *b = 0x40;
        }

        if let Some(report_data) = report_data {
            buf[body + REPORT_DATA_OFFSET..body + REPORT_DATA_OFFSET + REPORT_DATA_LEN]
                .copy_from_slice(&report_data);
        } else {
            // Report data: first 4 bytes = "cafe", rest 0xFF.
            buf[body + REPORT_DATA_OFFSET] = 0xCA;
            buf[body + REPORT_DATA_OFFSET + 1] = 0xFE;
            buf[body + REPORT_DATA_OFFSET + 2] = 0xBA;
            buf[body + REPORT_DATA_OFFSET + 3] = 0xBE;
            for b in
                &mut buf[body + REPORT_DATA_OFFSET + 4..body + REPORT_DATA_OFFSET + REPORT_DATA_LEN]
            {
                *b = 0xFF;
            }
        }

        buf
    }

    #[test]
    fn parse_extracts_measurements_at_expected_offsets() {
        let raw = build_fake_quote();
        let q = parse_tdx_quote(&raw).unwrap();

        assert_eq!(q.version, 4);
        assert_eq!(q.mrtd, [0xAA; 48]);
        assert_eq!(q.rtmrs[0], [0x10; 48]);
        assert_eq!(q.rtmrs[1], [0x20; 48]);
        assert_eq!(q.rtmrs[2], [0x30; 48]);
        assert_eq!(q.rtmrs[3], [0x40; 48]);

        // Verify hex helpers.
        assert!(q.mrtd_hex().chars().all(|c| c == 'a'));
        assert_eq!(q.mrtd_hex().len(), 96); // 48 bytes * 2 hex chars

        // Report data starts with cafebabe.
        assert!(q.report_data_hex().starts_with("cafebabe"));
    }

    #[test]
    fn parse_base64_quote() {
        let raw = build_fake_quote();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        let q = parse_tdx_quote_base64(&b64).unwrap();
        assert_eq!(q.version, 4);
        assert_eq!(q.mrtd, [0xAA; 48]);
    }

    #[test]
    fn parse_rejects_short_quote() {
        let short = vec![0u8; 100];
        let err = parse_tdx_quote(&short).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    #[test]
    fn report_data_nonce_prefix_check() {
        let raw = build_fake_quote();
        let q = parse_tdx_quote(&raw).unwrap();

        // The report data starts with 0xCA 0xFE 0xBA 0xBE → "cafebabe".
        assert!(report_data_starts_with_nonce_hex(&q, "cafebabe"));
        assert!(!report_data_starts_with_nonce_hex(&q, "deadbeef"));
    }

    #[test]
    fn quote_binding_matches_expected_noise_static() {
        let public_key = b"noise-static-public-key";
        let report_data = crate::attestation::report_data_for_noise_static(public_key);
        let raw = build_fake_quote_with_report_data(Some(report_data));
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);

        assert!(crate::attestation::verify_quote_binds_noise_static(&b64, public_key).is_ok());
        assert!(
            crate::attestation::verify_quote_binds_noise_static(&b64, b"different-public-key")
                .is_err()
        );
    }
}
