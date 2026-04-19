//! GitHub Actions OIDC verifier.
//!
//! GitHub Actions mints an OIDC JWT per job (issuer
//! `https://token.actions.githubusercontent.com`, JWKS at
//! `/.well-known/jwks`). A caller passes the token as
//! `Authorization: Bearer <jwt>`; the agent verifies the signature
//! against the cached JWKS and checks the required claims:
//!
//!   - `iss` matches the GitHub issuer
//!   - `aud` matches the configured audience (default `dd-agent`)
//!   - `repository_owner` matches `DD_OWNER` (the GitHub org)
//!
//! The claim `repository_owner` is the GitHub-signed org that the
//! Actions run belongs to. If a caller can produce a token with that
//! claim, the workflow must be running in the org — which is the
//! same trust boundary as a human org member.

use std::collections::HashMap;
use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::{Error, Result};

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const LEEWAY_SECS: u64 = 60;

const ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Claims {
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub repository: String,
    #[serde(default)]
    pub repository_owner: String,
    #[serde(default)]
    pub ref_: String,
    #[serde(default)]
    pub workflow: String,
}

pub struct Verifier {
    owner: String,
    audience: String,
    http: Client,
    keys: RwLock<HashMap<String, DecodingKey>>,
}

impl Verifier {
    pub fn new(owner: String, audience: String) -> Arc<Self> {
        Arc::new(Self {
            owner,
            audience,
            http: Client::new(),
            keys: RwLock::new(HashMap::new()),
        })
    }

    /// Verify a JWT, check the signature, issuer, audience, and
    /// `repository_owner` claim. Returns decoded claims on success.
    pub async fn verify(&self, token: &str) -> Result<Claims> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| Error::BadRequest(format!("gh oidc header: {e}")))?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(Error::BadRequest(format!(
                "gh oidc alg {:?} not allowed",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| Error::BadRequest("gh oidc token missing kid".into()))?;

        let key = match self.lookup(&kid).await {
            Some(k) => k,
            None => {
                self.refresh().await?;
                self.lookup(&kid)
                    .await
                    .ok_or_else(|| Error::BadRequest(format!("gh oidc kid {kid} not in JWKS")))?
            }
        };

        let mut v = Validation::new(header.alg);
        v.set_issuer(&[ISSUER]);
        v.set_audience(&[self.audience.as_str()]);
        v.leeway = LEEWAY_SECS;
        v.set_required_spec_claims(&["exp", "iat", "iss", "aud"]);

        let data = jsonwebtoken::decode::<serde_json::Value>(token, &key, &v)
            .map_err(|e| Error::BadRequest(format!("gh oidc verify: {e}")))?;

        let raw = data.claims;
        let claims = Claims {
            exp: raw.get("exp").and_then(|x| x.as_i64()).unwrap_or(0),
            iat: raw.get("iat").and_then(|x| x.as_i64()).unwrap_or(0),
            iss: raw.get("iss").and_then(|x| x.as_str()).unwrap_or("").into(),
            sub: raw.get("sub").and_then(|x| x.as_str()).unwrap_or("").into(),
            repository: raw
                .get("repository")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
            repository_owner: raw
                .get("repository_owner")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
            ref_: raw.get("ref").and_then(|x| x.as_str()).unwrap_or("").into(),
            workflow: raw
                .get("workflow")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
        };

        if claims.repository_owner != self.owner {
            return Err(Error::Unauthorized);
        }
        Ok(claims)
    }

    async fn lookup(&self, kid: &str) -> Option<DecodingKey> {
        self.keys.read().await.get(kid).cloned()
    }

    async fn refresh(&self) -> Result<()> {
        let resp = self
            .http
            .get(JWKS_URL)
            .send()
            .await
            .map_err(|e| Error::Upstream(format!("GH JWKS fetch: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Upstream(format!("GH JWKS: HTTP {}", resp.status())));
        }
        let jwks: jsonwebtoken::jwk::JwkSet = resp
            .json()
            .await
            .map_err(|e| Error::Upstream(format!("GH JWKS parse: {e}")))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reject_alg_none() {
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.";
        let v = Verifier::new("org".into(), "dd-agent".into());
        let err = v.verify(token).await.unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
    }

    #[tokio::test]
    async fn reject_hs256() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig";
        let v = Verifier::new("org".into(), "dd-agent".into());
        let err = v.verify(token).await.unwrap_err();
        match err {
            Error::BadRequest(m) => assert!(m.contains("alg")),
            e => panic!("expected BadRequest, got {e:?}"),
        }
    }
}
