//! Origin auth.
//!
//! During the Cloudflare Access migration we accept three presentations:
//!   - `Cf-Access-Jwt-Assertion` — preferred browser/service identity,
//!     signed by Cloudflare Access and validated locally by CP/agents.
//!   - `dd_auth` JWT cookie (HS256, `Domain=.{cf.domain}`) — legacy
//!     browser auth issued by the CP's `/auth/pat` POST.
//!   - `Authorization: Bearer <pat>` — legacy CI/curl path verified
//!     against GitHub.

use std::time::Duration;

use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{
    decode, decode_header, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::CfAccess;
use crate::error::{Error, Result};

pub const AUTH_COOKIE: &str = "dd_auth";
pub const COOKIE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const JWT_ALG: Algorithm = Algorithm::HS256;
const CF_ACCESS_JWT_ASSERTION: HeaderName = HeaderName::from_static("cf-access-jwt-assertion");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub login: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
}

/// Auth keys. CP has both halves; agents have verify-only (they receive
/// the secret from the CP in their register bootstrap response).
#[derive(Clone)]
pub struct Keys {
    signing: Option<EncodingKey>,
    decoding: DecodingKey,
    /// Used both for the `iss` claim on minted JWTs and for logging.
    pub issuer: String,
    /// Raw secret bytes, base64-encoded. The CP passes this to agents
    /// in their register response so they can verify the same JWTs.
    pub secret_b64: String,
}

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

impl Keys {
    /// Mint a fresh HS256 secret. Used by the CP on startup.
    pub fn fresh(issuer_host: &str) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        Self::from_secret(&bytes, issuer_host)
    }

    /// Build verify+sign keys from a known secret. Used by both CP
    /// (restoring) and agent (holds secret for verify only but sign
    /// is never called there).
    pub fn from_secret(bytes: &[u8], issuer_host: &str) -> Self {
        Self {
            signing: Some(EncodingKey::from_secret(bytes)),
            decoding: DecodingKey::from_secret(bytes),
            issuer: format!("https://{issuer_host}"),
            secret_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }

    /// Verify-only keys from a base64 secret delivered by the CP.
    pub fn from_b64(secret_b64: &str, issuer_host: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(secret_b64)
            .map_err(|e| Error::BadRequest(format!("jwt secret b64: {e}")))?;
        let mut k = Self::from_secret(&bytes, issuer_host);
        k.signing = None;
        Ok(k)
    }

    pub fn mint(&self, login: &str) -> Result<String> {
        let signing = self
            .signing
            .as_ref()
            .ok_or_else(|| Error::Internal("no signing key".into()))?;
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: login.to_string(),
            login: login.to_string(),
            iss: self.issuer.clone(),
            iat: now,
            exp: now + COOKIE_TTL.as_secs() as i64,
        };
        jsonwebtoken::encode(&Header::new(JWT_ALG), &claims, signing)
            .map_err(|e| Error::Internal(format!("jwt encode: {e}")))
    }

    pub fn verify(&self, jwt: &str) -> Option<Claims> {
        let mut v = Validation::new(JWT_ALG);
        v.set_required_spec_claims(&["exp", "sub", "iss"]);
        jsonwebtoken::decode::<Claims>(jwt, &self.decoding, &v)
            .ok()
            .map(|d| d.claims)
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

pub fn cookie(name: &str, value: &str, domain: Option<&str>, max_age: u64) -> String {
    let mut c =
        format!("{name}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}");
    if let Some(d) = domain {
        c.push_str(&format!("; Domain=.{d}"));
    }
    c
}

pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cs = headers.get(COOKIE)?.to_str().ok()?;
    for c in cs.split(';') {
        let mut kv = c.trim().splitn(2, '=');
        let k = kv.next()?.trim();
        let v = kv.next()?.trim();
        if k == name {
            return Some(v.to_string());
        }
    }
    None
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

pub fn with_cookie(resp: impl IntoResponse, cookie_value: String) -> Response {
    let mut r = resp.into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie_value) {
        r.headers_mut().append(SET_COOKIE, hv);
    }
    r
}

pub fn sanitize_next(next: Option<&str>) -> String {
    match next {
        Some(p) if p.starts_with('/') && !p.starts_with("//") => p.to_string(),
        _ => "/".to_string(),
    }
}

pub async fn resolve(
    keys: &Keys,
    owner: &str,
    access: Option<&AccessValidator>,
    headers: &HeaderMap,
) -> Result<String> {
    if let Some(access) = access {
        if let Some(principal) = access.resolve(headers).await? {
            return Ok(principal);
        }
    }
    if let Some(jwt) = read_cookie(headers, AUTH_COOKIE) {
        if let Some(c) = keys.verify(&jwt) {
            return Ok(c.login);
        }
    }
    if let Some(pat) = bearer(headers) {
        return verify_pat(&pat, owner).await;
    }
    Err(Error::Unauthorized)
}

/// Redirect unauthenticated browsers to the CP's PAT login.
pub fn login_redirect(cp_hostname: &str, uri: &Uri) -> Response {
    let next = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let location = format!(
        "https://{cp_hostname}/auth/pat?next={}",
        urlencoding::encode(&format!("https://{}{next}", cp_hostname))
    );
    Redirect::to(&location).into_response()
}

/// CP-local redirect for its own routes (no absolute URL needed).
pub fn login_redirect_local(uri: &Uri) -> Response {
    let next = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let location = format!("/auth/pat?next={}", urlencoding::encode(next));
    Redirect::to(&location).into_response()
}
