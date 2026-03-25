use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::common::error::{AppError, AppResult};

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/// Attestation claims extracted from an Intel Trust Authority JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationClaims {
    pub iss: String,
    #[serde(default)]
    pub aud: serde_json::Value,
    pub exp: u64,
    #[serde(default)]
    pub nbf: u64,
    /// TDX measurements — ITA nests these under a "tdx" object.
    #[serde(default)]
    pub tdx: Option<TdxClaims>,
    #[serde(default, rename = "attester_tcb_status")]
    pub attester_tcb_status: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Nested TDX-specific claims from the ITA attestation token.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TdxClaims {
    #[serde(default)]
    pub mrtd: Option<String>,
    #[serde(default)]
    pub rtmr0: Option<String>,
    #[serde(default)]
    pub rtmr1: Option<String>,
    #[serde(default)]
    pub rtmr2: Option<String>,
    #[serde(default)]
    pub rtmr3: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl AttestationClaims {
    /// Helper to get MRTD regardless of nesting.
    pub fn tdx_mrtd(&self) -> Option<&str> {
        self.tdx.as_ref().and_then(|t| t.mrtd.as_deref())
    }
}

// ---------------------------------------------------------------------------
// JWKS types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kid: Option<String>,
    pub kty: String,
    #[serde(default)]
    pub alg: Option<String>,
    // RSA fields
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    // Symmetric (oct) field
    #[serde(default)]
    pub k: Option<String>,
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

struct CachedJwks {
    document: JwksDocument,
    fetched_at: std::time::Instant,
}

/// Verifies Intel Trust Authority attestation tokens.
#[derive(Clone)]
pub struct ItaVerifier {
    jwks_url: String,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
    cache_ttl: std::time::Duration,
    cache: Arc<RwLock<Option<CachedJwks>>>,
}

impl ItaVerifier {
    pub fn new(
        jwks_url: String,
        expected_issuer: Option<String>,
        expected_audience: Option<String>,
    ) -> Self {
        Self {
            jwks_url,
            expected_issuer,
            expected_audience,
            cache_ttl: std::time::Duration::from_secs(3600),
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Verify an attestation JWT, returning the decoded claims.
    pub async fn verify_attestation_token(&self, token: &str) -> AppResult<AttestationClaims> {
        // Decode the header to get kid and alg
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| AppError::InvalidInput(format!("invalid token header: {e}")))?;

        let kid = header.kid.clone();
        let alg = header.alg;

        // Fetch (or use cached) JWKS
        let jwks = self.get_jwks().await?;

        // Find the matching key
        let jwk = if let Some(ref kid_val) = kid {
            jwks.keys
                .iter()
                .find(|k| k.kid.as_deref() == Some(kid_val))
                .ok_or_else(|| {
                    AppError::InvalidInput(format!("no JWKS key found for kid: {kid_val}"))
                })?
        } else {
            jwks.keys
                .first()
                .ok_or_else(|| AppError::InvalidInput("JWKS has no keys".into()))?
        };

        // Build the decoding key based on key type
        let decoding_key = match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk
                    .n
                    .as_ref()
                    .ok_or_else(|| AppError::InvalidInput("RSA key missing 'n'".into()))?;
                let e = jwk
                    .e
                    .as_ref()
                    .ok_or_else(|| AppError::InvalidInput("RSA key missing 'e'".into()))?;
                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| AppError::InvalidInput(format!("bad RSA key: {e}")))?
            }
            "oct" => {
                let k = jwk
                    .k
                    .as_ref()
                    .ok_or_else(|| AppError::InvalidInput("oct key missing 'k'".into()))?;
                let raw = URL_SAFE_NO_PAD
                    .decode(k)
                    .map_err(|e| AppError::InvalidInput(format!("bad base64 key: {e}")))?;
                DecodingKey::from_secret(&raw)
            }
            other => {
                return Err(AppError::InvalidInput(format!(
                    "unsupported key type: {other}"
                )));
            }
        };

        // Build validation
        let mut validation = Validation::new(alg);
        validation.validate_exp = true;
        validation.validate_nbf = false;

        if let Some(ref iss) = self.expected_issuer {
            validation.set_issuer(&[iss]);
        }

        if let Some(ref aud) = self.expected_audience {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }

        let token_data = decode::<AttestationClaims>(token, &decoding_key, &validation)
            .map_err(|e| AppError::InvalidInput(format!("token validation failed: {e}")))?;

        Ok(token_data.claims)
    }

    async fn get_jwks(&self) -> AppResult<JwksDocument> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(ref cached) = *cache {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(cached.document.clone());
                }
            }
        }

        // Fetch fresh JWKS
        let resp = reqwest::get(&self.jwks_url)
            .await
            .map_err(|e| AppError::External(format!("JWKS fetch failed: {e}")))?;

        let doc: JwksDocument = resp
            .json()
            .await
            .map_err(|e| AppError::External(format!("JWKS parse failed: {e}")))?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            *cache = Some(CachedJwks {
                document: doc.clone(),
                fetched_at: std::time::Instant::now(),
            });
        }

        Ok(doc)
    }
}

/// Map an algorithm name string to a jsonwebtoken Algorithm value.
#[allow(dead_code)]
pub fn algorithm_from_str(s: &str) -> Option<Algorithm> {
    match s {
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        "HS256" => Some(Algorithm::HS256),
        "HS384" => Some(Algorithm::HS384),
        "HS512" => Some(Algorithm::HS512),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn make_hs256_jwks_and_key() -> (JwksDocument, Vec<u8>) {
        let secret = b"test-secret-key-for-ita-verification-32b";
        let k = URL_SAFE_NO_PAD.encode(secret);
        (
            JwksDocument {
                keys: vec![Jwk {
                    kid: Some("test-kid-1".into()),
                    kty: "oct".into(),
                    alg: Some("HS256".into()),
                    n: None,
                    e: None,
                    k: Some(k),
                }],
            },
            secret.to_vec(),
        )
    }

    async fn verifier_with_cached_jwks(
        expected_issuer: Option<String>,
        expected_audience: Option<String>,
    ) -> (ItaVerifier, Vec<u8>) {
        let (jwks, secret) = make_hs256_jwks_and_key();
        let verifier = ItaVerifier::new(
            "https://unused.test/jwks".into(),
            expected_issuer,
            expected_audience,
        );

        {
            let mut cache = verifier.cache.write().await;
            *cache = Some(CachedJwks {
                document: jwks,
                fetched_at: std::time::Instant::now(),
            });
        }

        (verifier, secret)
    }

    fn make_token(secret: &[u8], claims: &AttestationClaims) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-kid-1".into());
        encode(&header, claims, &EncodingKey::from_secret(secret)).unwrap()
    }

    fn valid_claims() -> AttestationClaims {
        AttestationClaims {
            iss: "https://portal.trustauthority.intel.com".into(),
            aud: serde_json::Value::String("devopsdefender".into()),
            exp: (chrono::Utc::now().timestamp() + 3600) as u64,
            nbf: 0,
            tdx: Some(TdxClaims {
                mrtd: Some("abc123".into()),
                ..Default::default()
            }),
            attester_tcb_status: Some("UpToDate".into()),
            extra: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn verify_valid_token_with_mock_jwks() {
        let (verifier, secret) = verifier_with_cached_jwks(
            Some("https://portal.trustauthority.intel.com".into()),
            Some("devopsdefender".into()),
        )
        .await;

        let claims = valid_claims();
        let token = make_token(&secret, &claims);

        let result = verifier.verify_attestation_token(&token).await;
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.tdx_mrtd(), Some("abc123"));
    }

    #[tokio::test]
    async fn reject_expired_token() {
        let (verifier, secret) = verifier_with_cached_jwks(None, None).await;

        let mut claims = valid_claims();
        claims.exp = 1000; // way in the past
        let token = make_token(&secret, &claims);

        let result = verifier.verify_attestation_token(&token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn reject_wrong_audience() {
        let (verifier, secret) =
            verifier_with_cached_jwks(None, Some("wrong-audience".into())).await;

        let claims = valid_claims();
        let token = make_token(&secret, &claims);

        let result = verifier.verify_attestation_token(&token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn jwks_cache_reuse() {
        let (verifier, secret) = verifier_with_cached_jwks(None, None).await;

        let claims = valid_claims();
        let token1 = make_token(&secret, &claims);
        let token2 = make_token(&secret, &claims);

        let r1 = verifier.verify_attestation_token(&token1).await;
        assert!(r1.is_ok());
        let r2 = verifier.verify_attestation_token(&token2).await;
        assert!(r2.is_ok());
    }

    #[tokio::test]
    async fn accept_ps384_algorithm() {
        // Just verify the algorithm_from_str mapping works
        assert_eq!(algorithm_from_str("PS384"), Some(Algorithm::PS384));
        assert_eq!(algorithm_from_str("RS256"), Some(Algorithm::RS256));
        assert_eq!(algorithm_from_str("HS512"), Some(Algorithm::HS512));
        assert_eq!(algorithm_from_str("UNKNOWN"), None);
    }

    #[tokio::test]
    async fn allow_missing_audience_when_not_configured() {
        // No audience configured -- should accept any audience in token
        let (verifier, secret) = verifier_with_cached_jwks(None, None).await;

        let claims = valid_claims();
        let token = make_token(&secret, &claims);
        let result = verifier.verify_attestation_token(&token).await;
        assert!(result.is_ok());
    }
}
