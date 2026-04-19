//! Origin auth — Cloudflare Access JWT for browsers, GitHub PAT for programmatic callers.
//!
//! Two presentations, checked in order:
//!
//! - `Cf-Access-Jwt-Assertion` — the browser path. Validated locally
//!   against the account's Cloudflare Access JWKS; Access enforces
//!   identity at the edge and the app only needs to confirm the
//!   signature + audience + issuer.
//! - `Authorization: Bearer <pat>` — the programmatic path. Verified
//!   against GitHub (`/user`, `/user/orgs`, `/repos/{owner}/dd`). Used
//!   by agents for the /register + /ingress/replace handshake (those
//!   paths have a CF Access bypass app so Bearer calls reach the
//!   origin) and by any CI / curl client with a PAT.
//!
//! There is no in-app cookie any more — the dd_auth HS256 cookie + the
//! `/auth/pat` form that minted it are gone. Browsers authenticate via
//! CF Access; the `Cf-Access-Jwt-Assertion` header that CF injects
//! carries the identity we need.

use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderName};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::CfAccess;
use crate::error::{Error, Result};

const CF_ACCESS_JWT_ASSERTION: HeaderName = HeaderName::from_static("cf-access-jwt-assertion");

#[derive(Clone)]
pub struct AccessValidator {
    cfg: CfAccess,
    http: Client,
    jwks: Arc<RwLock<Option<JwkSet>>>,
}

impl AccessValidator {
    pub fn new(cfg: CfAccess) -> Self {
        Self {
            cfg,
            http: Client::new(),
            jwks: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn resolve(&self, headers: &HeaderMap) -> Result<Option<String>> {
        let Some(token) = access_token(headers) else {
            return Ok(None);
        };
        let claims = self.verify_token(token).await?;
        Ok(Some(access_principal(&claims)))
    }

    async fn verify_token(&self, token: &str) -> Result<serde_json::Value> {
        let header = decode_header(token).map_err(|_| Error::Unauthorized)?;
        if header.alg != Algorithm::RS256 {
            return Err(Error::Unauthorized);
        }
        let kid = header.kid.ok_or(Error::Unauthorized)?;

        let jwk = self.get_jwk(&kid).await?;
        match self.decode_with_jwk(token, &jwk) {
            Ok(claims) => Ok(claims),
            Err(_) => {
                // Access rotates signing keys; refresh once on failure
                // in case the cached set is stale but the token is valid.
                self.refresh_jwks().await?;
                let jwk = self.get_cached_jwk(&kid).await.ok_or(Error::Unauthorized)?;
                self.decode_with_jwk(token, &jwk)
                    .map_err(|_| Error::Unauthorized)
            }
        }
    }

    async fn get_jwk(&self, kid: &str) -> Result<Jwk> {
        if let Some(jwk) = self.get_cached_jwk(kid).await {
            return Ok(jwk);
        }
        self.refresh_jwks().await?;
        self.get_cached_jwk(kid).await.ok_or(Error::Unauthorized)
    }

    async fn get_cached_jwk(&self, kid: &str) -> Option<Jwk> {
        self.jwks
            .read()
            .await
            .as_ref()
            .and_then(|set| set.find(kid).cloned())
    }

    async fn refresh_jwks(&self) -> Result<()> {
        let resp = self
            .http
            .get(&self.cfg.jwks_url)
            .send()
            .await
            .map_err(|e| Error::Upstream(format!("CF Access certs: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Upstream(format!(
                "CF Access certs {} -> {status}: {text}",
                self.cfg.jwks_url
            )));
        }
        let jwks = resp.json::<JwkSet>().await?;
        *self.jwks.write().await = Some(jwks);
        Ok(())
    }

    fn decode_with_jwk(
        &self,
        token: &str,
        jwk: &Jwk,
    ) -> jsonwebtoken::errors::Result<serde_json::Value> {
        let key = DecodingKey::from_jwk(jwk)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_issuer(&[self.cfg.issuer.as_str()]);
        validation.set_audience(&self.cfg.audiences);
        decode::<serde_json::Value>(token, &key, &validation).map(|d| d.claims)
    }
}

/// Verify a GitHub PAT (or GITHUB_TOKEN) belongs to `owner` — either
/// the user `owner`, a member of org `owner`, or holds repo access to
/// `owner/dd`.
pub async fn verify_pat(pat: &str, owner: &str) -> Result<String> {
    let http = Client::new();
    let get = |url: String| {
        http.get(url)
            .bearer_auth(pat)
            .header("User-Agent", "devopsdefender")
            .send()
    };

    // Probe 1: /user. User PATs succeed; GITHUB_TOKEN 403s (it's
    // repo-scoped). Failure must NOT short-circuit — fall through to
    // the repo probe so the Actions workflow-token path works.
    let mut login = String::new();
    if let Ok(resp) = get("https://api.github.com/user".into()).await {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                login = body["login"].as_str().unwrap_or_default().to_string();
                if login == owner {
                    return Ok(login);
                }
            }
        }
    }

    // Probe 2: /user/orgs (membership).
    if let Ok(resp) = get("https://api.github.com/user/orgs".into()).await {
        if let Ok(orgs) = resp.json::<Vec<serde_json::Value>>().await {
            if orgs.iter().any(|o| o["login"].as_str() == Some(owner)) {
                return Ok(login);
            }
        }
    }

    // Probe 3: /repos/{owner}/dd — the canonical GITHUB_TOKEN path.
    if let Ok(resp) = get(format!("https://api.github.com/repos/{owner}/dd")).await {
        if resp.status().is_success() {
            return Ok(if login.is_empty() {
                "actions".into()
            } else {
                login
            });
        }
    }

    Err(Error::Unauthorized)
}

pub fn bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn access_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(CF_ACCESS_JWT_ASSERTION)?
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn access_principal(claims: &serde_json::Value) -> String {
    for key in ["email", "common_name", "sub"] {
        if let Some(v) = claims.get(key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    "cf-access".into()
}

/// Resolve the caller's identity. CF Access header wins (browsers);
/// Bearer PAT is the fallback for programmatic callers that bypass
/// Access (or hit `/register` + `/ingress/replace`, which have CF
/// Access bypass apps in front of them).
pub async fn resolve(access: &AccessValidator, owner: &str, headers: &HeaderMap) -> Result<String> {
    if let Some(principal) = access.resolve(headers).await? {
        return Ok(principal);
    }
    if let Some(pat) = bearer(headers) {
        return verify_pat(&pat, owner).await;
    }
    Err(Error::Unauthorized)
}
