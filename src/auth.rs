//! HS256 JWT cookie middleware shared by CP and agent.
//!
//! The CP issues `dd_session` cookies at `/oauth/callback` (see
//! `src/oauth.rs`). Both CP and agent verify them with the same shared
//! secret (`DD_FLEET_JWT_SECRET`). This module is just verification +
//! a small extractor; minting lives in `oauth.rs`.

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

pub const COOKIE_NAME: &str = "dd_session";
pub const SESSION_TTL_SECS: i64 = 30 * 60;

/// JWT claims for `dd_session` cookies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    /// GitHub login of the human.
    pub sub: String,
    /// Numeric GitHub user id (for re-registered-login defence).
    pub uid: u64,
    /// Fleet (`DD_OWNER`) — sanity check that a stolen cookie from
    /// another fleet doesn't unlock this one.
    pub fleet: String,
    /// Issued-at, seconds since epoch.
    pub iat: i64,
    /// Expiry, seconds since epoch.
    pub exp: i64,
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub claims: SessionClaims,
}

/// Mint a fresh `dd_session` cookie value (JWT-encoded).
pub fn mint(secret: &str, sub: String, uid: u64, fleet: String) -> Result<String, String> {
    let now = chrono::Utc::now().timestamp();
    let claims = SessionClaims {
        sub,
        uid,
        fleet,
        iat: now,
        exp: now + SESSION_TTL_SECS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| e.to_string())
}

/// Verify a `dd_session` cookie value (JWT). Returns the claims on
/// success.
pub fn verify(secret: &str, token: &str, expected_fleet: &str) -> Result<SessionClaims, String> {
    let mut v = Validation::new(Algorithm::HS256);
    v.set_required_spec_claims(&["exp", "iat", "sub"]);
    v.leeway = 30;
    let data = decode::<SessionClaims>(token, &DecodingKey::from_secret(secret.as_bytes()), &v)
        .map_err(|e| e.to_string())?;
    if data.claims.fleet != expected_fleet {
        return Err(format!(
            "cookie fleet={:?} does not match expected={expected_fleet:?}",
            data.claims.fleet
        ));
    }
    Ok(data.claims)
}

/// Extract a Cookie header into a (name, value) iterator. Trims OWS
/// per RFC 6265 §5.4. Tolerates malformed segments.
pub fn parse_cookies(header: &str) -> impl Iterator<Item = (&str, &str)> {
    header.split(';').filter_map(|seg| {
        let seg = seg.trim();
        seg.split_once('=').map(|(k, v)| (k.trim(), v.trim()))
    })
}

pub fn extract_session_cookie(parts: &Parts) -> Option<String> {
    let cookie_header = parts.headers.get(header::COOKIE)?.to_str().ok()?;
    parse_cookies(cookie_header)
        .find(|(k, _)| *k == COOKIE_NAME)
        .map(|(_, v)| v.to_string())
}

/// Build a `Set-Cookie` header value for the session cookie.
///
/// `Domain=.{fleet_domain}` so the cookie is sent to both
/// `app.<domain>` (CP) and any `<agent>.<domain>` subdomain.
pub fn set_cookie_header(value: &str, fleet_domain: &str) -> String {
    format!(
        "{COOKIE_NAME}={value}; Domain=.{fleet_domain}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={SESSION_TTL_SECS}"
    )
}

pub fn clear_cookie_header(fleet_domain: &str) -> String {
    format!(
        "{COOKIE_NAME}=; Domain=.{fleet_domain}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
    )
}

/// Per-mode shared state needed for cookie verification. Both CP::St
/// and agent::St expose this via `FromRef` so the extractor can be
/// generic.
#[derive(Clone)]
pub struct CookieAuthState {
    pub fleet_jwt_secret: String,
    pub expected_fleet: String,
    /// Where to redirect unauthenticated browser requests. CP redirects
    /// to its own `/login`. Agents redirect to the CP's `/login`.
    pub login_url: String,
}

impl<S> FromRequestParts<S> for Identity
where
    S: Send + Sync,
    CookieAuthState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let cfg: CookieAuthState = CookieAuthState::from_ref(state);
        let token = match extract_session_cookie(parts) {
            Some(t) => t,
            None => return Err(redirect_or_unauth(parts, &cfg.login_url)),
        };
        match verify(&cfg.fleet_jwt_secret, &token, &cfg.expected_fleet) {
            Ok(claims) => Ok(Identity { claims }),
            Err(e) => {
                tracing_log(parts, &format!("cookie verify fail: {e}"));
                Err(redirect_or_unauth(parts, &cfg.login_url))
            }
        }
    }
}

fn redirect_or_unauth(parts: &Parts, login_url: &str) -> Response {
    let wants_html = parts
        .headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/html"))
        .unwrap_or(false);
    if wants_html {
        Redirect::to(login_url).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
    }
}

fn tracing_log(parts: &Parts, msg: &str) {
    eprintln!("auth {} {} {msg}", parts.method, parts.uri.path());
}
