//! Intel Trust Authority (ITA) — mint + verify.
//!
//! The agent fetches a raw TDX quote from easyenclave, POSTs it to
//! `api.trustauthority.intel.com/appraisal/v1/attest` with an x-api-key
//! header, and receives a signed JWT ("ITA token"). That JWT is
//! forwarded in the register payload. The CP verifies the signature
//! against Intel's JWKS, checks issuer + exp + algorithm allowlist,
//! and stores the decoded claims on the agent record.
//!
//! Fail open: if an agent has no `DD_ITA_API_KEY` it registers without
//! a token. The CP accepts unsigned registrations unless `DD_ITA_REQUIRED=true`.

use std::collections::HashMap;
use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::{Error, Result};

/// Algorithms we accept on ITA-issued tokens. Explicitly excludes
/// `HS*` (symmetric — can't verify against a JWKS) and `none`.
const ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::EdDSA,
];

const LEEWAY_SECS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Claims {
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub tcb_status: Option<String>,
    #[serde(default)]
    pub attester_type: Option<String>,
    #[serde(default)]
    pub mrtd: Option<String>,
    #[serde(default)]
    pub mrsigner: Option<String>,
    #[serde(default)]
    pub report_data: Option<String>,
    /// Full body, preserved so the dashboard can show anything the
    /// typed fields above don't cover.
    #[serde(default)]
    pub extra: serde_json::Value,
}

impl Claims {
    fn from_value(v: serde_json::Value) -> Self {
        // Map Intel's wire names to our normalized ones.
        let get = |k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
        Self {
            exp: v.get("exp").and_then(|x| x.as_i64()).unwrap_or(0),
            iat: v.get("iat").and_then(|x| x.as_i64()).unwrap_or(0),
            tcb_status: get("attester_tcb_status"),
            attester_type: get("attester_type"),
            mrtd: get("tdx_mrtd"),
            mrsigner: get("tdx_mrsigner"),
            report_data: get("attester_held_data"),
            extra: v,
        }
    }
}

// ── Minter ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct MintRequest<'a> {
    quote: &'a str,
}

#[derive(Deserialize)]
struct MintResponse {
    token: String,
}

/// POST a base64 TDX quote to Intel, receive a signed JWT. `base_url`
/// is typically `https://api.trustauthority.intel.com`.
pub async fn mint(base_url: &str, api_key: &str, quote_b64: &str) -> Result<String> {
    let url = format!("{}/appraisal/v1/attest", base_url.trim_end_matches('/'));
    let resp = Client::new()
        .post(&url)
        .header("x-api-key", api_key)
        .header("Accept", "application/json")
        .json(&MintRequest { quote: quote_b64 })
        .send()
        .await
        .map_err(|e| Error::Upstream(format!("ITA mint {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Upstream(format!("ITA mint {status}: {body}")));
    }
    let body: MintResponse = resp.json().await?;
    Ok(body.token)
}

// ── Verifier ────────────────────────────────────────────────────────────

/// Caches the JWKS in memory. Refreshes on unknown `kid`; otherwise
/// serves from cache indefinitely (Intel rotates rarely).
pub struct Verifier {
    jwks_url: String,
    issuer: String,
    http: Client,
    keys: RwLock<HashMap<String, DecodingKey>>,
}

impl Verifier {
    pub fn new(jwks_url: String, issuer: String) -> Arc<Self> {
        Arc::new(Self {
            jwks_url,
            issuer,
            http: Client::new(),
            keys: RwLock::new(HashMap::new()),
        })
    }

    /// Verify a JWT. Returns decoded claims on success.
    pub async fn verify(&self, token: &str) -> Result<Claims> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| Error::BadRequest(format!("ita header: {e}")))?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(Error::BadRequest(format!(
                "ita alg {:?} not allowed",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| Error::BadRequest("ita token missing kid".into()))?;

        let key = match self.lookup(&kid).await {
            Some(k) => k,
            None => {
                self.refresh().await?;
                self.lookup(&kid)
                    .await
                    .ok_or_else(|| Error::BadRequest(format!("ita kid {kid} not in JWKS")))?
            }
        };

        let mut v = Validation::new(header.alg);
        v.set_issuer(&[&self.issuer]);
        v.leeway = LEEWAY_SECS;
        v.set_required_spec_claims(&["exp", "iat", "iss"]);

        let data = jsonwebtoken::decode::<serde_json::Value>(token, &key, &v)
            .map_err(|e| Error::BadRequest(format!("ita verify: {e}")))?;
        Ok(Claims::from_value(data.claims))
    }

    async fn lookup(&self, kid: &str) -> Option<DecodingKey> {
        // DecodingKey isn't Clone, so we can't return a reference to a
        // cached entry outliving the lock. Re-derive from the cached
        // JWK instead — we store the raw JWK bytes and reconstruct.
        self.keys.read().await.get(kid).cloned()
    }

    async fn refresh(&self) -> Result<()> {
        let resp = self
            .http
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| Error::Upstream(format!("JWKS fetch {}: {e}", self.jwks_url)))?;
        if !resp.status().is_success() {
            return Err(Error::Upstream(format!(
                "JWKS {}: HTTP {}",
                self.jwks_url,
                resp.status()
            )));
        }
        let jwks: jsonwebtoken::jwk::JwkSet = resp
            .json()
            .await
            .map_err(|e| Error::Upstream(format!("JWKS parse: {e}")))?;

        let mut map = HashMap::new();
        for jwk in &jwks.keys {
            let kid = match &jwk.common.key_id {
                Some(k) => k.clone(),
                None => continue,
            };
            if let Ok(dk) = DecodingKey::from_jwk(jwk) {
                map.insert(kid, dk);
            }
        }
        *self.keys.write().await = map;
        Ok(())
    }
}

// ── Convenience for DecodingKey cloning ─────────────────────────────────
// jsonwebtoken::DecodingKey is Clone in 9.x, so the HashMap<String, DecodingKey>
// above works directly. (Left as a comment so we notice if that changes.)

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reject_algorithm_none() {
        // Header {"alg":"none"}, empty sig. Base64url("{\"alg\":\"none\",\"typ\":\"JWT\"}")
        // . Base64url("{}") . "".
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.";
        let v = Verifier::new("http://127.0.0.1:1/".into(), "x".into());
        let err = v.verify(token).await.unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn reject_hs256() {
        // alg=HS256 — not in our allowlist, must fail on alg check alone.
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature_placeholder";
        let v = Verifier::new("http://127.0.0.1:1/".into(), "x".into());
        let err = v.verify(token).await.unwrap_err();
        match err {
            Error::BadRequest(m) => assert!(m.contains("alg"), "msg: {m}"),
            e => panic!("expected BadRequest, got {e:?}"),
        }
    }

    #[test]
    fn claims_map_intel_wire_names() {
        let v = serde_json::json!({
            "exp": 123, "iat": 1,
            "attester_tcb_status": "UpToDate",
            "attester_type": "TDX",
            "tdx_mrtd": "aa",
            "tdx_mrsigner": "bb",
            "attester_held_data": "cc",
        });
        let c = Claims::from_value(v.clone());
        assert_eq!(c.exp, 123);
        assert_eq!(c.tcb_status.as_deref(), Some("UpToDate"));
        assert_eq!(c.mrtd.as_deref(), Some("aa"));
        assert_eq!(c.mrsigner.as_deref(), Some("bb"));
        assert_eq!(c.report_data.as_deref(), Some("cc"));
        assert_eq!(c.extra, v);
    }
}
