//! Intel Trust Authority (ITA) TDX quote verifier.
//!
//! Flow:
//!   1. POST the base64-encoded TDX quote to `{base}/appraisal/v1/attest`
//!      with `x-api-key: {DD_ITA_API_KEY}`. ITA returns a signed JWT
//!      (`{"token": "..."}`).
//!   2. Fetch ITA's JWKS at `{base}/certs` and verify the token signature
//!      against the `kid` named in its header.
//!   3. Assert the quote's `REPORT_DATA` begins with the handshake nonce
//!      we sent in Noise msg2. This binds the quote to *this* handshake,
//!      preventing an attacker from replaying a stolen valid quote.
//!
//! What this does NOT enforce yet: a policy_ids list pinning the
//! expected MRTD/RTMR measurements to our image. Until we have captured
//! known-good values from a trusted build, verification only confirms
//! "this is a valid TDX quote per Intel" + nonce freshness, not "this
//! is our specific easyenclave image." The claims returned here are
//! logged by handler.rs so ops can capture measurements from prod.

use base64::Engine;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ItaError {
    #[error("ita request failed: {0}")]
    Request(String),
    #[error("ita returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("token parse: {0}")]
    Token(String),
    #[error("jwks fetch: {0}")]
    Jwks(String),
    #[error("key id {0} not found in jwks")]
    KeyNotFound(String),
    #[error("report_data does not bind to handshake nonce")]
    NonceMismatch,
}

pub struct ItaVerifier {
    api_key: String,
    base_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct AttestResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

/// Subset of ITA token claims. ITA emits many more fields; we parse the
/// TDX measurements (for logging + future policy use) and the report
/// data (for nonce binding).
#[derive(Debug, Deserialize, Clone)]
pub struct ItaClaims {
    /// Hex-encoded 64-byte REPORT_DATA from the quote.
    #[serde(rename = "attester_tdx_reportdata")]
    pub report_data: Option<String>,
    #[serde(rename = "attester_tdx_mrtd")]
    pub mrtd: Option<String>,
    #[serde(rename = "attester_tdx_rtmr0")]
    pub rtmr0: Option<String>,
    #[serde(rename = "attester_tdx_rtmr1")]
    pub rtmr1: Option<String>,
    #[serde(rename = "attester_tdx_rtmr2")]
    pub rtmr2: Option<String>,
    #[serde(rename = "attester_tdx_rtmr3")]
    pub rtmr3: Option<String>,
    #[serde(rename = "attester_tcb_status")]
    pub tcb_status: Option<String>,
}

impl ItaVerifier {
    pub fn new(api_key: String, base_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            api_key,
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Verify a TDX quote against ITA and assert its REPORT_DATA begins
    /// with `handshake_nonce_b64`. Returns the measurement claims for
    /// logging on success.
    pub async fn verify(
        &self,
        quote_b64: &str,
        handshake_nonce_b64: &str,
    ) -> Result<ItaClaims, ItaError> {
        // 1. POST quote to ITA.
        let resp = self
            .client
            .post(format!("{}/appraisal/v1/attest", self.base_url))
            .header("x-api-key", &self.api_key)
            .header("Accept", "application/json")
            .json(&serde_json::json!({ "quote": quote_b64 }))
            .send()
            .await
            .map_err(|e| ItaError::Request(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ItaError::Status {
                status: status.as_u16(),
                body,
            });
        }
        let attest: AttestResponse = resp
            .json()
            .await
            .map_err(|e| ItaError::Request(format!("decode body: {e}")))?;

        // 2. Verify token signature via JWKS.
        let header = decode_header(&attest.token).map_err(|e| ItaError::Token(e.to_string()))?;
        let kid = header
            .kid
            .clone()
            .ok_or_else(|| ItaError::Token("jwt header missing kid".into()))?;
        let alg = header.alg;
        let key = self.fetch_jwk(&kid).await?;
        let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e)
            .map_err(|e| ItaError::Token(format!("decoding key: {e}")))?;
        let mut validation = Validation::new(alg);
        // ITA's `iss`/`aud` vary by region/tenant; TLS + x-api-key is our
        // trust root for which ITA instance we're talking to. Default
        // Validation already skips iss if set_issuer isn't called; turn
        // off aud checking so we don't reject tokens with an audience
        // claim the caller hasn't pre-registered.
        validation.validate_aud = false;
        let token_data = decode::<ItaClaims>(&attest.token, &decoding_key, &validation)
            .map_err(|e| ItaError::Token(format!("verify: {e}")))?;

        // 3. Nonce binding. easyenclave places our handshake nonce in
        //    the leading bytes of REPORT_DATA when requesting the quote;
        //    ITA returns REPORT_DATA hex-encoded.
        let report_data = token_data
            .claims
            .report_data
            .as_deref()
            .ok_or(ItaError::NonceMismatch)?;
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(handshake_nonce_b64)
            .map_err(|_| ItaError::NonceMismatch)?;
        let nonce_hex = hex_lower(&nonce_bytes);
        if !report_data.to_ascii_lowercase().starts_with(&nonce_hex) {
            return Err(ItaError::NonceMismatch);
        }

        Ok(token_data.claims)
    }

    async fn fetch_jwk(&self, kid: &str) -> Result<Jwk, ItaError> {
        let resp = self
            .client
            .get(format!("{}/certs", self.base_url))
            .send()
            .await
            .map_err(|e| ItaError::Jwks(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ItaError::Jwks(format!("status {}", resp.status())));
        }
        let jwks: JwksResponse = resp
            .json()
            .await
            .map_err(|e| ItaError::Jwks(format!("decode jwks: {e}")))?;
        jwks.keys
            .into_iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| ItaError::KeyNotFound(kid.to_string()))
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
