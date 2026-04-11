//! Authentication: password mode, register-issued JWT, and GitHub PAT fallback.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use dd_common::error::AppError;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::AppState;

// ── Constants ───────────────────────────────────────────────────────────

const SESSION_COOKIE: &str = "dd_session";
const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);

/// Register-issued auth token cookie (domain-scoped to .devopsdefender.com).
const AUTH_COOKIE: &str = "dd_auth";

const PASSWORD_SESSION_MARKER: &str = "password-session";

// ── Session types ───────────────────────────────────────────────────────

pub struct BrowserSession {
    pub token: String,
    pub expires_at: Instant,
}

pub type BrowserSessions = Arc<Mutex<HashMap<String, BrowserSession>>>;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuthClaims {
    pub sub: String,
    pub login: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub next: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub password: String,
    pub next: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DashQuery {
    pub token: Option<String>,
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn extract_auth(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or(value.strip_prefix("bearer "))?;
    Some(token.to_string())
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(COOKIE)?.to_str().ok()?;
    for cookie in cookies.split(';') {
        let mut parts = cookie.trim().splitn(2, '=');
        let key = parts.next()?.trim();
        let value = parts.next()?.trim();
        if key == name {
            return Some(value.to_string());
        }
    }
    None
}

fn sanitize_next_path(next: Option<&str>) -> String {
    match next {
        Some(path) if path.starts_with('/') && !path.starts_with("//") => path.to_string(),
        _ => "/".to_string(),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn is_secure_cookies(state: &AppState) -> bool {
    state.config.hostname.is_some()
}

fn build_session_cookie(state: &AppState, session_id: &str, max_age: u64) -> String {
    let mut cookie =
        format!("{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if is_secure_cookies(state) {
        cookie.push_str("; Secure");
    }
    cookie
}

fn response_with_cookie(response: impl IntoResponse, cookie: String) -> Response {
    let mut response = response.into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}

async fn session_token_from_cookie(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let session_id = extract_cookie(headers, SESSION_COOKIE)?;
    let mut sessions = state.browser_sessions.lock().await;
    let now = Instant::now();
    sessions.retain(|_, session| session.expires_at > now);
    sessions
        .get(&session_id)
        .map(|session| session.token.clone())
}

// ── GitHub token verification ───────────────────────────────────────────

async fn verify_github_token(token: &str, owner: &str) -> Result<(), AppError> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "dd-client")
        .send()
        .await
        .map_err(|_| AppError::Unauthorized)?;
    if !resp.status().is_success() {
        return Err(AppError::Unauthorized);
    }
    let user: serde_json::Value = resp.json().await.map_err(|_| AppError::Unauthorized)?;
    let login = user["login"].as_str().unwrap_or("");
    if login == owner {
        return Ok(());
    }
    // Check orgs
    let orgs_resp = client
        .get("https://api.github.com/user/orgs")
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "dd-client")
        .send()
        .await
        .map_err(|_| AppError::Unauthorized)?;
    if orgs_resp.status().is_success() {
        let orgs: Vec<serde_json::Value> =
            orgs_resp.json().await.map_err(|_| AppError::Unauthorized)?;
        for org in &orgs {
            if org["login"].as_str() == Some(owner) {
                return Ok(());
            }
        }
    }
    Err(AppError::Unauthorized)
}

// ── Core auth resolution ────────────────────────────────────────────────

/// Resolve the authenticated user from headers.
/// Returns `Ok(Some(login))` on success, `Ok(None)` if no owner is set,
/// or `Err(Unauthorized)` if auth fails.
pub async fn resolve_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<String>, AppError> {
    if state.config.owner.is_empty() {
        return Ok(None);
    }

    // 1. Register-issued dd_auth JWT cookie
    if let Some(ref decoding_key) = state.auth_public_key {
        if let Some(jwt) = extract_cookie(headers, AUTH_COOKIE) {
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
            validation.validate_exp = true;
            if let Ok(data) = jsonwebtoken::decode::<AuthClaims>(&jwt, decoding_key, &validation) {
                if !data.claims.login.is_empty() {
                    return Ok(Some(data.claims.login));
                }
            }
        }
    }

    // 2. Session cookie (password sessions)
    if let Some(token) = session_token_from_cookie(state, headers).await {
        if token == PASSWORD_SESSION_MARKER {
            return Ok(Some(token));
        }
        // GitHub session token: accept it
        return Ok(Some(token));
    }

    // 3. Password mode: check Authorization header
    if let Some(ref password) = state.config.password {
        if let Some(token) = extract_auth(headers) {
            if constant_time_eq(token.as_bytes(), password.as_bytes()) {
                return Ok(Some("password-bearer".to_string()));
            }
            return Err(AppError::Unauthorized);
        }
    }

    // 4. GitHub PAT fallback: Bearer token verified against GitHub
    if let Some(token) = extract_auth(headers) {
        if verify_github_token(&token, &state.config.owner)
            .await
            .is_ok()
        {
            return Ok(Some("github-pat".to_string()));
        }
    }

    Err(AppError::Unauthorized)
}

/// Verify the caller is the owner. Convenience wrapper around resolve_auth.
pub async fn verify_owner(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    resolve_auth(state, headers).await.map(|_| ())
}

/// For browser pages: resolve auth, and on failure redirect to login.
pub async fn require_browser_token(
    state: &AppState,
    headers: &HeaderMap,
    query_token: Option<&str>,
    current_uri: &Uri,
) -> Result<Option<String>, Response> {
    // Try query token first (for shared links)
    if let Some(token) = query_token.filter(|t| !t.is_empty()) {
        if let Some(ref password) = state.config.password {
            if constant_time_eq(token.as_bytes(), password.as_bytes()) {
                return Ok(Some("query-token".to_string()));
            }
        }
    }

    match resolve_auth(state, headers).await {
        Ok(token) => Ok(token),
        Err(AppError::Unauthorized) if state.config.password.is_some() => {
            // Redirect to login page
            let next_path = current_uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            let location = format!("/auth/login?next={}", urlencoding::encode(next_path));
            Err(Redirect::to(&location).into_response())
        }
        Err(AppError::Unauthorized) if state.auth_issuer.is_some() => {
            let issuer = state.auth_issuer.as_deref().unwrap();
            Err(Redirect::to(issuer).into_response())
        }
        Err(err) => Err(err.into_response()),
    }
}

/// Reconstruct auth decoding key from a base64-encoded secret.
pub fn auth_key_from_b64(b64: &str) -> Option<jsonwebtoken::DecodingKey> {
    let secret = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).ok()?;
    Some(jsonwebtoken::DecodingKey::from_secret(&secret))
}

// ── Login handlers ──────────────────────────────────────────────────────

pub async fn login_page(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Query(query): axum::extract::Query<LoginQuery>,
) -> Html<String> {
    let hostname = state
        .config
        .hostname
        .as_deref()
        .unwrap_or(&state.config.vm_name);
    let next = sanitize_next_path(query.next.as_deref());
    let error_html = if query.error.is_some() {
        r#"<div class="error">Incorrect password</div>"#
    } else {
        ""
    };

    Html(format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — DevOps Defender</title>
<style>
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:#1e1e2e; color:#cdd6f4; font-family:'JetBrains Mono',ui-monospace,monospace; display:flex; align-items:center; justify-content:center; min-height:100vh; }}
  .card {{ background:#181825; border:1px solid #313244; border-radius:12px; padding:32px; width:100%; max-width:360px; }}
  h1 {{ color:#89b4fa; font-size:18px; margin:0 0 4px; }}
  .sub {{ color:#585b70; font-size:12px; margin-bottom:24px; }}
  label {{ display:block; color:#a6adc8; font-size:12px; text-transform:uppercase; margin-bottom:6px; }}
  input[type=password] {{ width:100%; padding:10px 12px; background:#11111b; border:1px solid #313244; border-radius:6px; color:#cdd6f4; font-family:inherit; font-size:14px; outline:none; }}
  input[type=password]:focus {{ border-color:#89b4fa; }}
  button {{ width:100%; padding:10px; margin-top:16px; background:#89b4fa; color:#1e1e2e; border:none; border-radius:6px; font-family:inherit; font-size:14px; font-weight:600; cursor:pointer; }}
  button:hover {{ background:#74c7ec; }}
  .error {{ color:#f38ba8; font-size:13px; margin-bottom:12px; }}
</style></head><body>
<div class="card">
  <h1>DevOps Defender</h1>
  <div class="sub">{hostname}</div>
  {error}
  <form method="POST" action="/auth/login">
    <input type="hidden" name="next" value="{next}">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autofocus>
    <button type="submit">Sign in</button>
  </form>
</div>
</body></html>"#,
        hostname = hostname,
        error = error_html,
        next = next,
    ))
}

pub async fn login_submit(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Form(form): axum::extract::Form<LoginForm>,
) -> Response {
    let expected = match state.config.password {
        Some(ref password) => password.as_bytes(),
        None => return AppError::Config("Password auth not configured".into()).into_response(),
    };

    let next = sanitize_next_path(form.next.as_deref());

    if !constant_time_eq(form.password.as_bytes(), expected) {
        let location = format!(
            "/auth/login?error=invalid&next={}",
            urlencoding::encode(&next)
        );
        return Redirect::to(&location).into_response();
    }

    let session_id = uuid::Uuid::new_v4().simple().to_string();
    state.browser_sessions.lock().await.insert(
        session_id.clone(),
        BrowserSession {
            token: PASSWORD_SESSION_MARKER.into(),
            expires_at: Instant::now() + SESSION_TTL,
        },
    );

    response_with_cookie(
        Redirect::to(&next),
        build_session_cookie(&state, &session_id, SESSION_TTL.as_secs()),
    )
}

pub async fn logout(axum::extract::State(state): axum::extract::State<AppState>) -> Response {
    response_with_cookie(
        Redirect::to("/auth/login"),
        build_session_cookie(&state, "", 0),
    )
}
