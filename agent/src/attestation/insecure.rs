//! Insecure attestation backend — no hardware proof. Works everywhere.

use super::AttestationBackend;
use serde_json::Value;

pub struct InsecureBackend;

impl AttestationBackend for InsecureBackend {
    fn attestation_type(&self) -> &str {
        "insecure"
    }

    fn generate_quote_b64_with_report_data(&self, _report_data: &[u8]) -> Option<String> {
        None
    }

    fn health_metadata(&self) -> Value {
        serde_json::json!({
            "attestation_type": "insecure",
            "note": "no hardware attestation available"
        })
    }
}
