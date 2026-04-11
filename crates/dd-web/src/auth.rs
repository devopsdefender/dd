use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use dd_common::error::AppError;

use crate::html::page_shell;
use crate::state::{BrowserSession, PendingOauthState, WebState};

const SESSION_COOKIE: &str = "dd_session";
const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);
const OAUTH_STATE_TTL: Duration = Duration::from_secs(10 * 60);

/// Register-issued auth token cookie (domain-scoped).
const AUTH_COOKIE: &str = "dd_auth";
const AUTH_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);

// ── Query types ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthStartQuery {
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GithubCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuthClaims {
    pub sub: String,
    pub login: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
}

// ── Cookie helpers ───────────────────────────────────────────────────────

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

fn build_session_cookie(session_id: &str, max_age: u64) -> String {
    format!(
        "{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}"
    )
}

fn response_with_cookie(response: impl IntoResponse, cookie: String) -> Response {
    let mut response = response.into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}

fn github_oauth_redirect(next: &Uri) -> Redirect {
    let mut url = reqwest::Url::parse("http://localhost/auth/github/start").unwrap();
    let next_path = next
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    url.query_pairs_mut().append_pair("next", next_path);
    let location = format!("{}?{}", url.path(), url.query().unwrap_or_default());
    Redirect::to(&location)
}

// ── Auth verification ────────────────────────────────────────────────────

/// Validate a dd_auth JWT from the cookie.
fn validate_auth_jwt(state: &WebState, headers: &HeaderMap) -> Option<AuthClaims> {
    let token = extract_cookie(headers, AUTH_COOKIE)?;
    let validation = {
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        v.validate_exp = true;
        v.set_required_spec_claims(&["exp", "sub", "iss"]);
        v
    };
    jsonwebtoken::decode::<AuthClaims>(&token, &state.decoding_key, &validation)
        .ok()
        .map(|data| data.claims)
}

/// Validate browser session cookie.
async fn session_token_from_cookie(state: &WebState, headers: &HeaderMap) -> Option<String> {
    let session_id = extract_cookie(headers, SESSION_COOKIE)?;
    let mut sessions = state.sessions.lock().await;
    let now = Instant::now();
    sessions.retain(|_, session| session.expires_at > now);
    sessions
        .get(&session_id)
        .map(|session| session.token.clone())
}

/// Extract a bearer token from the Authorization header.
fn bearer_from_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Resolve authentication -- returns Ok(Some(login)) if authenticated, Err if rejected.
async fn resolve_auth(state: &WebState, headers: &HeaderMap) -> Result<Option<String>, AppError> {
    // DD_OWNER is now required in Config::from_env — if we reach here
    // it's always non-empty. (Previously an empty owner silently
    // disabled all auth, which was a fail-open bug.)
    debug_assert!(!state.config.owner.is_empty());

    // 1. Check dd_auth JWT (domain-scoped cookie)
    if let Some(claims) = validate_auth_jwt(state, headers) {
        return Ok(Some(claims.login));
    }

    // 2. Check local session cookie
    if let Some(_token) = session_token_from_cookie(state, headers).await {
        return Ok(Some("session".to_string()));
    }

    // 3-4. Bearer token: try GitHub Actions OIDC first (canonical CI
    //      auth, zero secrets, claims-based), fall back to PAT/OAuth
    //      token via verify_github_token for manual scripting with a
    //      real user PAT (e.g. `curl -H "Bearer $(gh auth token)"`).
    if let Some(token) = bearer_from_header(headers) {
        // Structural check: GitHub OIDC tokens are 3-segment RS256 JWTs.
        // PATs and github.token are opaque strings. Skip the JWKS fetch
        // for non-JWT-shaped tokens.
        let looks_like_jwt = token.matches('.').count() == 2;

        if looks_like_jwt {
            if let Some(audience) = state.config.oidc_audience.as_deref() {
                if let Ok(repo) = verify_github_oidc(&token, &state.config.owner, audience).await {
                    return Ok(Some(format!("github-oidc:{repo}")));
                }
            }
        }

        if verify_github_token(&token, &state.config.owner)
            .await
            .is_ok()
        {
            return Ok(Some("github-pat".to_string()));
        }
    }

    Err(AppError::Unauthorized)
}

/// Require browser authentication, redirecting to GitHub OAuth if not authed.
pub async fn require_browser_auth(
    state: &WebState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<Option<String>, Response> {
    match resolve_auth(state, headers).await {
        Ok(login) => Ok(login),
        Err(AppError::Unauthorized) => Err(github_oauth_redirect(uri).into_response()),
        Err(e) => Err(e.into_response()),
    }
}

// ── GitHub OAuth token verification ──────────────────────────────────────

async fn verify_github_token(token: &str, owner: &str) -> Result<(), AppError> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "dd-web")
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
    // Check org membership
    let orgs_resp = client
        .get("https://api.github.com/user/orgs")
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "dd-web")
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

    // GitHub Actions GITHUB_TOKEN fallback -- check repo access
    let repo_resp = client
        .get(format!("https://api.github.com/repos/{owner}/dd"))
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "dd-web")
        .send()
        .await;
    if let Ok(resp) = repo_resp {
        if resp.status().is_success() {
            return Ok(());
        }
    }

    Err(AppError::Unauthorized)
}

// ── GitHub Actions OIDC token verification ──────────────────────────────
//
// Canonical "auth from a GitHub Action" pattern: the workflow mints an
// OIDC JWT via $ACTIONS_ID_TOKEN_REQUEST_URL with a custom audience,
// dd-web verifies the signature against GitHub's JWKS and checks claims.
// No secrets, no API calls to github.com/user, no rate limits.

const GH_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GH_OIDC_JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";

#[derive(serde::Deserialize)]
struct GithubOidcClaims {
    repository: String,
    repository_owner: String,
}

/// Verify a GitHub Actions OIDC token. Returns the `repository` claim
/// on success. Enforces signature (RS256 via JWKS), issuer, audience,
/// exp/nbf (via Validation defaults), and `repository_owner == owner`.
async fn verify_github_oidc(token: &str, owner: &str, audience: &str) -> Result<String, AppError> {
    // TODO(perf): cache JWKS with a ~10 min TTL. Fetch-per-request is
    // fine for low CI volume (a handful of auth checks per deploy).
    let jwks: jsonwebtoken::jwk::JwkSet = reqwest::get(GH_OIDC_JWKS_URL)
        .await
        .map_err(|_| AppError::Unauthorized)?
        .json()
        .await
        .map_err(|_| AppError::Unauthorized)?;

    let header = jsonwebtoken::decode_header(token).map_err(|_| AppError::Unauthorized)?;
    let kid = header.kid.ok_or(AppError::Unauthorized)?;
    let jwk = jwks.find(&kid).ok_or(AppError::Unauthorized)?;
    let key = jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|_| AppError::Unauthorized)?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[GH_OIDC_ISSUER]);
    validation.set_audience(&[audience]);

    let data = jsonwebtoken::decode::<GithubOidcClaims>(token, &key, &validation)
        .map_err(|_| AppError::Unauthorized)?;

    if data.claims.repository_owner != owner {
        return Err(AppError::Unauthorized);
    }

    Ok(data.claims.repository)
}

// ── Route handlers ───────────────────────────────────────────────────────

/// GET /auth/github/start -- redirect to GitHub OAuth
pub async fn github_start(
    State(state): State<WebState>,
    query: axum::extract::Query<AuthStartQuery>,
) -> Result<Redirect, AppError> {
    let next_path = sanitize_next_path(query.next.as_deref());
    let state_id = uuid::Uuid::new_v4().simple().to_string();

    state.pending_oauth_states.lock().await.insert(
        state_id.clone(),
        PendingOauthState {
            next_path,
            expires_at: Instant::now() + OAUTH_STATE_TTL,
        },
    );

    let mut url = reqwest::Url::parse("https://github.com/login/oauth/authorize").unwrap();
    url.query_pairs_mut()
        .append_pair("client_id", &state.config.github_client_id)
        .append_pair("redirect_uri", &state.config.github_callback_url)
        .append_pair("scope", "read:user read:org")
        .append_pair("state", &state_id);
    Ok(Redirect::to(url.as_str()))
}

/// GET /auth/github/callback -- exchange code, verify, issue JWT
pub async fn github_callback(
    State(state): State<WebState>,
    query: axum::extract::Query<GithubCallbackQuery>,
) -> Result<Response, AppError> {
    if let Some(error) = query.error.as_deref() {
        let description = query.error_description.as_deref().unwrap_or(error);
        return Err(AppError::External(description.into()));
    }

    let code = query
        .code
        .as_deref()
        .ok_or_else(|| AppError::InvalidInput("missing GitHub OAuth code".into()))?;
    let state_id = query
        .state
        .as_deref()
        .ok_or_else(|| AppError::InvalidInput("missing GitHub OAuth state".into()))?;

    let next_path = {
        let mut states = state.pending_oauth_states.lock().await;
        let now = Instant::now();
        states.retain(|_, pending| pending.expires_at > now);
        states
            .remove(state_id)
            .map(|pending| pending.next_path)
            .ok_or(AppError::Unauthorized)?
    };

    // Exchange code for access token
    let http = reqwest::Client::new();
    let token_resp = http
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .header("User-Agent", "dd-web")
        .form(&[
            ("client_id", state.config.github_client_id.as_str()),
            ("client_secret", state.config.github_client_secret.as_str()),
            ("code", code),
            ("redirect_uri", state.config.github_callback_url.as_str()),
            ("state", state_id),
        ])
        .send()
        .await
        .map_err(|e| AppError::External(format!("GitHub OAuth exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        return Err(AppError::Unauthorized);
    }

    let token_body: GithubTokenResponse = token_resp
        .json()
        .await
        .map_err(|e| AppError::External(format!("invalid GitHub OAuth response: {e}")))?;
    let token = token_body.access_token.ok_or(AppError::Unauthorized)?;

    if !state.config.owner.is_empty() {
        verify_github_token(&token, &state.config.owner).await?;
    }

    // Create local session
    let session_id = uuid::Uuid::new_v4().simple().to_string();
    state.sessions.lock().await.insert(
        session_id.clone(),
        BrowserSession {
            token: token.clone(),
            expires_at: Instant::now() + SESSION_TTL,
        },
    );

    let mut response = response_with_cookie(
        Redirect::to(&next_path),
        build_session_cookie(&session_id, SESSION_TTL.as_secs()),
    );

    // Issue domain-scoped dd_auth JWT
    let login = match http
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "dd-web")
        .send()
        .await
    {
        Ok(resp) => resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v["login"].as_str().map(String::from))
            .unwrap_or_default(),
        Err(_) => String::new(),
    };

    let now = chrono::Utc::now().timestamp();
    let claims = AuthClaims {
        sub: login.clone(),
        login,
        iss: format!("https://{}", state.config.hostname),
        iat: now,
        exp: now + AUTH_TOKEN_TTL.as_secs() as i64,
    };
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    if let Ok(jwt) = jsonwebtoken::encode(&header, &claims, &state.signing_key) {
        let domain = &state.config.domain;
        let cookie = format!(
            "{AUTH_COOKIE}={jwt}; Path=/; Domain=.{domain}; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
            AUTH_TOKEN_TTL.as_secs()
        );
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(SET_COOKIE, value);
        }
    }

    Ok(response)
}

/// GET /auth/logout -- clear session + dd_auth cookies
pub async fn logout(State(state): State<WebState>, headers: HeaderMap) -> Response {
    if let Some(session_id) = extract_cookie(&headers, SESSION_COOKIE) {
        state.sessions.lock().await.remove(&session_id);
    }

    let domain = &state.config.domain;
    let clear_auth = format!(
        "{AUTH_COOKIE}=; Path=/; Domain=.{domain}; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
    );

    let mut response =
        response_with_cookie(Redirect::to("/logged-out"), build_session_cookie("", 0));
    if let Ok(value) = HeaderValue::from_str(&clear_auth) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}

/// GET /logged-out -- simple confirmation page
pub async fn logged_out_page() -> Html<String> {
    let content = r#"<h1>Logged out</h1>
<div class="sub">Session cleared.</div>
<p><a href="/auth/github/start?next=/">Log in again</a></p>"#;
    let nav = "";
    Html(page_shell("Logged out -- DD Fleet", nav, content))
}
