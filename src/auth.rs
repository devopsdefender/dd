//! Single-path auth.
//!
//! One token type: GitHub PAT. Two presentations:
//!   - `Authorization: Bearer <pat>` — CI, curl. Verified against GitHub.
//!   - `dd_auth` JWT cookie (HS256, `Domain=.{cf.domain}`) — browsers.
//!     Issued only by the CP's `/auth/pat` POST; shared across all
//!     `*.{cf.domain}` hosts, so agents verify it without ever issuing.

use std::time::Duration;

use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const AUTH_COOKIE: &str = "dd_auth";
pub const COOKIE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const JWT_ALG: Algorithm = Algorithm::HS256;

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

pub async fn resolve(keys: &Keys, owner: &str, headers: &HeaderMap) -> Result<String> {
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
