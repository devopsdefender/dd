mod deploy;
mod register;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{OriginalUri, Path, State, WebSocketUpgrade};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

use dd_agent::common::error::AppError;
use dd_agent::tunnel::CfConfig;

pub use deploy::{
    execute_deploy, execute_deploy_with_handles, execute_stop, DeployRequest, DeploymentInfo,
    Deployments, ProcessHandles,
};

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentSummary {
    pub app_name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Argv of the most recent post_deploy step (if any).
    /// Useful for CI to identify which step a failed deploy stopped on
    /// without exposing stdout/stderr on the unauthenticated /health endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_step_cmd: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_step_exit_code: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub agent_id: String,
    pub vm_name: String,
    pub owner: String,
    pub attestation_type: String,
    pub deployment_count: usize,
    pub deployments: Vec<String>,
    /// All deployments with status + last-step metadata, regardless of state.
    /// `deployments` above keeps the existing running-only Vec<String> shape for
    /// back-compat; this field is the richer view CI uses to detect failures.
    /// Stdout/stderr are deliberately *not* exposed here — fetch
    /// /deployments/{id} (auth required) for full output.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub all_deployments: Vec<DeploymentSummary>,
    pub uptime_seconds: u64,
    pub cpu_percent: u64,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub disk_used_gb: u64,
    pub disk_total_gb: u64,
}

pub type BrowserSessions = Arc<Mutex<HashMap<String, BrowserSession>>>;
pub type PendingOauthStates = Arc<Mutex<HashMap<String, PendingOauthState>>>;

#[derive(Debug, Clone)]
pub struct GithubOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub callback_url: String,
    pub secure_cookies: bool,
}

impl GithubOAuthConfig {
    pub fn from_env() -> Result<Option<Self>, String> {
        let client_id = std::env::var("DD_GITHUB_CLIENT_ID").ok();
        let client_secret = std::env::var("DD_GITHUB_CLIENT_SECRET").ok();
        let callback_url = std::env::var("DD_GITHUB_CALLBACK_URL").ok();

        match (client_id, client_secret, callback_url) {
            (None, None, None) => Ok(None),
            (Some(client_id), Some(client_secret), Some(callback_url)) => Ok(Some(Self {
                client_id,
                client_secret,
                secure_cookies: callback_url.starts_with("https://"),
                callback_url,
            })),
            _ => Err(
                "DD_GITHUB_CLIENT_ID, DD_GITHUB_CLIENT_SECRET, and DD_GITHUB_CALLBACK_URL must all be set"
                    .into(),
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrowserSession {
    pub token: String,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct PendingOauthState {
    pub next_path: String,
    pub expires_at: Instant,
}

/// Agent record in the fleet registry (register mode only).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisteredAgent {
    pub agent_id: String,
    pub hostname: String,
    pub vm_name: String,
    pub attestation_type: String,
    pub registered_at: String,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub status: String,
    pub deployment_count: usize,
    pub deployment_names: Vec<String>,
    pub cpu_percent: u64,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
}

pub type AgentRegistry = Arc<Mutex<HashMap<String, RegisteredAgent>>>;

/// Authentication mode for the dashboard.
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// No local auth — allow all (dev mode), or rely on register-issued JWT only.
    None,
    /// GitHub OAuth (used by register agent / marketplace hub).
    GitHub(GithubOAuthConfig),
    /// Simple shared password (used by marketplace agents).
    Password {
        password: String,
        secure_cookies: bool,
    },
}

#[derive(Clone)]
pub struct AgentState {
    pub owner: String,
    pub vm_name: String,
    pub agent_id: String,
    pub attestation_type: String,
    pub deployments: Deployments,
    pub process_handles: ProcessHandles,
    pub started_at: std::time::Instant,
    pub auth_mode: AuthMode,
    pub browser_sessions: BrowserSessions,
    pub pending_oauth_states: PendingOauthStates,
    /// Register mode: fleet registry + CF config for creating agent tunnels.
    pub register_mode: bool,
    pub agent_registry: AgentRegistry,
    pub cf_config: Option<CfConfig>,
    /// Register-issued auth: Ed25519 keypair (register) or public key (agent).
    pub auth_signing_key: Option<jsonwebtoken::EncodingKey>,
    pub auth_public_key_decoded: Option<jsonwebtoken::DecodingKey>,
    /// Register URL for auth redirects (agents redirect here when dd_auth cookie is missing).
    pub auth_issuer: Option<String>,
    /// Base64-encoded Ed25519 public key (to send to agents during bootstrap).
    pub auth_public_key_b64: Option<String>,
}

fn browser_ui_enabled(state: &AgentState) -> bool {
    state.register_mode
        || std::env::var("DD_AGENT_BROWSER_UI")
            .ok()
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

// ── Auth ──────────────────────────────────────────────────────────────────

const SESSION_COOKIE: &str = "dd_session";
const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);
const OAUTH_STATE_TTL: Duration = Duration::from_secs(10 * 60);

/// Register-issued auth token cookie (domain-scoped to .devopsdefender.com).
const AUTH_COOKIE: &str = "dd_auth";
const AUTH_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthClaims {
    pub sub: String,
    pub login: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
}

/// Generate a random HMAC-SHA256 secret for register-issued auth tokens.
/// Returns (EncodingKey, DecodingKey, base64-encoded secret for distribution to agents).
pub fn generate_auth_secret() -> (jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey, String) {
    // Use two UUIDv4s (128 bits each) for 256 bits of randomness
    let mut secret = Vec::with_capacity(32);
    secret.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    secret.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &secret);
    let encoding = jsonwebtoken::EncodingKey::from_secret(&secret);
    let decoding = jsonwebtoken::DecodingKey::from_secret(&secret);
    (encoding, decoding, b64)
}

/// Reconstruct auth keys from a base64-encoded secret (used by agents).
pub fn auth_keys_from_b64(
    b64: &str,
) -> Option<(jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey)> {
    let secret = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).ok()?;
    Some((
        jsonwebtoken::EncodingKey::from_secret(&secret),
        jsonwebtoken::DecodingKey::from_secret(&secret),
    ))
}

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

fn is_secure_cookies(state: &AgentState) -> bool {
    match &state.auth_mode {
        AuthMode::GitHub(oauth) => oauth.secure_cookies,
        AuthMode::Password { secure_cookies, .. } => *secure_cookies,
        AuthMode::None => false,
    }
}

fn build_session_cookie(state: &AgentState, session_id: &str, max_age: u64) -> String {
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

async fn session_token_from_cookie(state: &AgentState, headers: &HeaderMap) -> Option<String> {
    let session_id = extract_cookie(headers, SESSION_COOKIE)?;
    let mut sessions = state.browser_sessions.lock().await;
    let now = Instant::now();
    sessions.retain(|_, session| session.expires_at > now);
    sessions
        .get(&session_id)
        .map(|session| session.token.clone())
}

const PASSWORD_SESSION_MARKER: &str = "password-session";

async fn resolve_auth(
    state: &AgentState,
    headers: &HeaderMap,
    query_token: Option<&str>,
) -> Result<Option<String>, AppError> {
    if state.owner.is_empty() {
        return Ok(None);
    }

    // 1. Check register-issued dd_auth JWT cookie first (works for all auth modes)
    if let Some(ref decoding_key) = state.auth_public_key_decoded {
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

    // 2. Check session cookie (works for both GitHub and password sessions)
    if let Some(token) = session_token_from_cookie(state, headers).await {
        // Password sessions use a marker — no GitHub verification needed
        if token == PASSWORD_SESSION_MARKER {
            return Ok(Some(token));
        }
        // GitHub sessions: token is a GitHub access token, accept it
        return Ok(Some(token));
    }

    // 3. Password-mode: check Authorization header against DD_PASSWORD
    if let AuthMode::Password { ref password, .. } = state.auth_mode {
        if let Some(token) = extract_auth(headers) {
            if constant_time_eq(token.as_bytes(), password.as_bytes()) {
                return Ok(Some("password-bearer".to_string()));
            }
            return Err(AppError::Unauthorized);
        }
    }

    // 4. GitHub-mode only: check query param and Authorization header
    if matches!(state.auth_mode, AuthMode::GitHub(_)) {
        if let Some(token) = query_token.filter(|token| !token.is_empty()) {
            verify_github_token(token, &state.owner).await?;
            return Ok(Some(token.to_string()));
        }

        if let Some(token) = extract_auth(headers) {
            verify_github_token(&token, &state.owner).await?;
            return Ok(Some(token));
        }
    }

    Err(AppError::Unauthorized)
}

fn auth_redirect(state: &AgentState, current_uri: &Uri) -> Redirect {
    match &state.auth_mode {
        AuthMode::GitHub(_) => github_oauth_redirect(current_uri),
        AuthMode::Password { .. } => {
            let mut url = reqwest::Url::parse("http://localhost/auth/login").unwrap();
            let next_path = current_uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            url.query_pairs_mut().append_pair("next", next_path);
            let location = format!("{}?{}", url.path(), url.query().unwrap_or_default());
            Redirect::to(&location)
        }
        AuthMode::None => Redirect::to("/auth/login"),
    }
}

async fn require_browser_token(
    state: &AgentState,
    headers: &HeaderMap,
    query_token: Option<&str>,
    current_uri: &Uri,
) -> Result<Option<String>, Response> {
    match resolve_auth(state, headers, query_token).await {
        Ok(token) => Ok(token),
        Err(AppError::Unauthorized)
            if matches!(
                state.auth_mode,
                AuthMode::GitHub(_) | AuthMode::Password { .. }
            ) =>
        {
            Err(auth_redirect(state, current_uri).into_response())
        }
        Err(AppError::Unauthorized) if state.auth_issuer.is_some() => {
            // Redirect to register for auth. After login, the dd_auth cookie
            // (scoped to .devopsdefender.com) will be set, and the user
            // can return to this agent.
            let issuer = state.auth_issuer.as_deref().unwrap();
            Err(Redirect::to(issuer).into_response())
        }
        Err(err) => Err(err.into_response()),
    }
}

async fn verify_owner(state: &AgentState, headers: &HeaderMap) -> Result<(), AppError> {
    resolve_auth(state, headers, None).await.map(|_| ())
}

// ── HTTP Handlers (read-only) ────────────────────────────────────────────

async fn health(State(state): State<AgentState>) -> Json<HealthResponse> {
    let deps = state.deployments.lock().await;
    let deployment_count = deps.len();
    let deployment_names: Vec<String> = deps
        .values()
        .filter(|d| d.status == "running")
        .map(|d| d.app_name.clone())
        .collect();
    let all_deployments: Vec<DeploymentSummary> = deps
        .values()
        .map(|d| {
            let last_step = d.post_deploy_steps.last();
            DeploymentSummary {
                app_name: d.app_name.clone(),
                status: d.status.clone(),
                error_message: d.error_message.clone(),
                last_step_cmd: last_step.map(|s| s.cmd.clone()),
                last_step_exit_code: last_step.map(|s| s.exit_code),
            }
        })
        .collect();
    drop(deps);
    let metrics = collect_metrics().await;
    Json(HealthResponse {
        ok: true,
        agent_id: state.agent_id.clone(),
        vm_name: state.vm_name.clone(),
        owner: state.owner.clone(),
        attestation_type: state.attestation_type.clone(),
        deployment_count,
        deployments: deployment_names,
        all_deployments,
        uptime_seconds: state.started_at.elapsed().as_secs(),
        cpu_percent: metrics.cpu_pct,
        memory_used_mb: parse_size_mb(&metrics.mem_used),
        memory_total_mb: parse_size_mb(&metrics.mem_total),
        disk_used_gb: parse_size_gb(&metrics.disk_used),
        disk_total_gb: parse_size_gb(&metrics.disk_total),
    })
}

fn parse_size_mb(s: &str) -> u64 {
    if let Some(g) = s.strip_suffix('G') {
        (g.parse::<f64>().unwrap_or(0.0) * 1024.0) as u64
    } else if let Some(m) = s.strip_suffix('M') {
        m.parse::<f64>().unwrap_or(0.0) as u64
    } else {
        0
    }
}

fn parse_size_gb(s: &str) -> u64 {
    if let Some(g) = s.strip_suffix('G') {
        g.parse::<f64>().unwrap_or(0.0) as u64
    } else {
        0
    }
}

// ── Shared page shell (Catppuccin Mocha theme) ──────────────────────────

const CATPPUCCIN_CSS: &str = r#"
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:#1e1e2e; color:#cdd6f4; font-family:'JetBrains Mono',ui-monospace,monospace; }
  a { color:#89b4fa; text-decoration:none; } a:hover { text-decoration:underline; }
  nav { display:flex; align-items:center; gap:16px; padding:12px 24px; border-bottom:1px solid #313244; }
  nav .brand { color:#89b4fa; font-weight:700; font-size:14px; }
  nav a { color:#a6adc8; font-size:13px; } nav a:hover, nav a.active { color:#cdd6f4; }
  nav .spacer { flex:1; }
  main { max-width:960px; margin:0 auto; padding:24px; }
  h1 { color:#89b4fa; font-size:20px; margin-bottom:4px; }
  .sub { color:#585b70; font-size:12px; margin-bottom:16px; }
  .meta { color:#a6adc8; font-size:13px; margin-bottom:24px; }
  .meta .ok { color:#a6e3a1; }
  .section { color:#a6adc8; font-size:12px; text-transform:uppercase; margin:20px 0 8px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-bottom:16px; }
  .card { background:#181825; border:1px solid #313244; border-radius:8px; padding:16px; }
  .card .label { color:#a6adc8; font-size:11px; text-transform:uppercase; }
  .card .value { font-size:20px; margin-top:4px; }
  .card .value.green { color:#a6e3a1; }
  .card .value.blue { color:#89b4fa; }
  .card .value.peach { color:#fab387; }
  .card .value.mauve { color:#cba6f7; }
  .row { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #313244; }
  .row:last-child { border-bottom:none; }
  table { border-collapse:collapse; width:100%; }
  th { text-align:left; color:#a6adc8; font-weight:normal; font-size:12px; text-transform:uppercase; padding:8px 12px; border-bottom:1px solid #313244; }
  td { padding:8px 12px; border-bottom:1px solid #313244; font-size:14px; }
  .pill { display:inline-block; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
  .pill.healthy, .pill.running { background:#a6e3a122; color:#a6e3a1; }
  .pill.stale, .pill.deploying { background:#fab38722; color:#fab387; }
  .pill.dead, .pill.failed, .pill.exited { background:#f38ba822; color:#f38ba8; }
  .pill.idle { background:#31324488; color:#a6adc8; }
  .empty { color:#585b70; padding:24px; text-align:center; }
  .dim { color:#585b70; }
  .back { font-size:13px; margin-bottom:20px; }
  @media(max-width:640px) { main { padding:16px; } .cards { grid-template-columns:1fr 1fr; } }
"#;

fn page_shell(title: &str, nav_html: &str, content: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>{css}</style></head><body>
{nav}
<main>{content}</main>
</body></html>"#,
        title = title,
        css = CATPPUCCIN_CSS,
        nav = nav_html,
        content = content,
    )
}

fn nav_bar(items: &[(&str, &str, bool)]) -> String {
    let mut html = String::from(r#"<nav><span class="brand">DD</span>"#);
    for (label, href, active) in items {
        if *active {
            html.push_str(&format!(r#"<a href="{href}" class="active">{label}</a>"#));
        } else {
            html.push_str(&format!(r#"<a href="{href}">{label}</a>"#));
        }
    }
    html.push_str(r#"<span class="spacer"></span><a href="/auth/logout">log out</a></nav>"#);
    html
}

fn nav_bar_with_terminal(items: &[(&str, &str, bool)]) -> String {
    let mut html = String::from(r#"<nav><span class="brand">DD</span>"#);
    for (label, href, active) in items {
        if *active {
            html.push_str(&format!(r#"<a href="{href}" class="active">{label}</a>"#));
        } else {
            html.push_str(&format!(r#"<a href="{href}">{label}</a>"#));
        }
    }
    html.push_str(r#"<span class="spacer"></span><form method="POST" action="/terminal" style="display:inline"><button type="submit" style="background:#a6e3a1;color:#1e1e2e;border:none;border-radius:4px;padding:4px 12px;font-family:inherit;font-size:13px;font-weight:600;cursor:pointer">+ Terminal</button></form> <a href="/auth/logout">log out</a></nav>"#);
    html
}

fn format_uptime(secs: u64) -> String {
    if secs > 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs > 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

async fn logged_out_page() -> Html<String> {
    let content = r#"<div style="text-align:center;padding:80px 0">
<h1>Signed out</h1>
<p style="color:#a6adc8;margin-top:12px">Your session has been cleared.</p>
<p style="margin-top:16px"><a href="/">Return to dashboard</a></p>
</div>"#;
    Html(page_shell("Signed out — DD", "", content))
}

async fn list_deployments(
    State(state): State<AgentState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeploymentInfo>>, AppError> {
    verify_owner(&state, &headers).await?;
    let deps = state.deployments.lock().await;
    Ok(Json(deps.values().cloned().collect()))
}

async fn get_deployment(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeploymentInfo>, AppError> {
    verify_owner(&state, &headers).await?;
    let deps = state.deployments.lock().await;
    let info = deps.get(&id).ok_or(AppError::NotFound)?;
    Ok(Json(info.clone()))
}

async fn deployment_logs(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_owner(&state, &headers).await?;
    let (pid, container_id) = {
        let deps = state.deployments.lock().await;
        let info = deps.get(&id).ok_or(AppError::NotFound)?;
        (info.pid, info.container_id.clone())
    };
    let logs: Vec<String> = if let Some(cid) = container_id {
        dd_agent::container::logs(&cid, 100)
            .await
            .unwrap_or_default()
    } else if let Some(pid) = pid {
        let log_path = format!("/var/lib/dd/workloads/logs/{pid}.log");
        let content = tokio::fs::read_to_string(&log_path)
            .await
            .unwrap_or_default();
        content
            .lines()
            .rev()
            .take(100)
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    } else {
        vec![]
    };
    Ok(Json(serde_json::json!({ "logs": logs })))
}

// ── Workload detail page ─────────────────────────────────────────────────

async fn workload_page(
    State(state): State<AgentState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, AppError> {
    if !state.owner.is_empty() {
        match require_browser_token(&state, &headers, None, &uri).await {
            Ok(_) => {}
            Err(response) => return Ok(response),
        }
    }

    let d = {
        let deps = state.deployments.lock().await;
        deps.get(&id).cloned().ok_or(AppError::NotFound)?
    };

    let status_class = match d.status.as_str() {
        "running" => "running",
        "deploying" => "deploying",
        "failed" | "exited" => "failed",
        _ => "idle",
    };

    let session_link = if d.status == "running" {
        format!(
            r#"<a href="/session/{name}">Open terminal session</a>"#,
            name = d.app_name
        )
    } else {
        String::new()
    };

    let error_row = d
        .error_message
        .as_deref()
        .filter(|e| !e.is_empty())
        .map(|e| {
            format!(
                r#"<div class="row"><span class="label">Error</span><span style="color:#f38ba8">{e}</span></div>"#
            )
        })
        .unwrap_or_default();

    // Read logs (container via bollard, process via log file)
    let logs = if let Some(ref cid) = d.container_id {
        let lines = dd_agent::container::logs(cid, 200)
            .await
            .unwrap_or_default();
        lines
            .iter()
            .map(|l| {
                l.replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else if let Some(pid) = d.pid {
        let log_path = format!("/var/lib/dd/workloads/logs/{pid}.log");
        let content = tokio::fs::read_to_string(&log_path)
            .await
            .unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();
        let tail: Vec<&str> = if lines.len() > 200 {
            lines[lines.len() - 200..].to_vec()
        } else {
            lines
        };
        tail.iter()
            .map(|l| {
                l.replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        String::new()
    };

    let nav = nav_bar_with_terminal(&[("Dashboard", "/", false)]);
    let content = format!(
        r#"<div class="back"><a href="/">&larr; dashboard</a></div>
<h1>{name}</h1>
<div class="sub">{id}</div>

<div class="card">
  <div class="row"><span class="label">Status</span><span class="pill {status_class}">{status}</span></div>
  <div class="row"><span class="label">Image</span><span>{image}</span></div>
  <div class="row"><span class="label">Started</span><span>{started}</span></div>
  {error_row}
</div>

{session_link}

<div class="section">Logs (last 200 lines)</div>
<pre style="background:#11111b;border:1px solid #313244;border-radius:8px;padding:16px;overflow-x:auto;font-size:12px;line-height:1.5;max-height:60vh;overflow-y:auto;color:#a6adc8">{logs}</pre>"#,
        name = d.app_name,
        id = id,
        status_class = status_class,
        status = d.status,
        image = d.image,
        started = d.started_at,
        error_row = error_row,
        session_link = session_link,
        logs = if logs.is_empty() {
            "<span class=\"dim\">No logs available</span>".into()
        } else {
            logs
        },
    );

    Ok(Html(page_shell(&format!("DD — {}", d.app_name), &nav, &content)).into_response())
}

// ── Web terminal ─────────────────────────────────────────────────────────

async fn session_page(
    State(state): State<AgentState>,
    Path(app_name): Path<String>,
    query: axum::extract::Query<SessionQuery>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, AppError> {
    if !state.owner.is_empty() {
        match require_browser_token(&state, &headers, query.token.as_deref(), &uri).await {
            Ok(_) => {}
            Err(response) => return Ok(response),
        }
    }

    let html = include_str!("../../../../web/terminal.html");
    Ok(Html(html.replace("DD Terminal", &format!("DD — {app_name}"))).into_response())
}

#[derive(Debug, serde::Deserialize)]
struct SessionQuery {
    token: Option<String>,
}

async fn ws_session(
    State(state): State<AgentState>,
    Path(app_name): Path<String>,
    query: axum::extract::Query<SessionQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    resolve_auth(&state, &headers, query.token.as_deref()).await?;
    Ok(ws.on_upgrade(move |socket| handle_ws_session(socket, state, app_name)))
}

#[derive(Debug, Deserialize)]
struct AuthStartQuery {
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
}

async fn github_auth_start(
    State(state): State<AgentState>,
    query: axum::extract::Query<AuthStartQuery>,
) -> Result<Redirect, AppError> {
    let AuthMode::GitHub(ref oauth) = state.auth_mode else {
        return Err(AppError::Config("GitHub OAuth is not configured".into()));
    };
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
        .append_pair("client_id", &oauth.client_id)
        .append_pair("redirect_uri", &oauth.callback_url)
        .append_pair("scope", "read:user read:org")
        .append_pair("state", &state_id);
    Ok(Redirect::to(url.as_str()))
}

async fn github_auth_callback(
    State(state): State<AgentState>,
    query: axum::extract::Query<GithubCallbackQuery>,
) -> Result<Response, AppError> {
    if let Some(error) = query.error.as_deref() {
        let description = query.error_description.as_deref().unwrap_or(error);
        return Err(AppError::External(description.into()));
    }

    let AuthMode::GitHub(ref oauth) = state.auth_mode else {
        return Err(AppError::Config("GitHub OAuth is not configured".into()));
    };
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

    let http = reqwest::Client::new();
    let token_resp = http
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .header("User-Agent", "dd-agent")
        .form(&[
            ("client_id", oauth.client_id.as_str()),
            ("client_secret", oauth.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", oauth.callback_url.as_str()),
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

    if !state.owner.is_empty() {
        verify_github_token(&token, &state.owner).await?;
    }

    let session_id = uuid::Uuid::new_v4().simple().to_string();
    state.browser_sessions.lock().await.insert(
        session_id.clone(),
        BrowserSession {
            token: token.clone(),
            expires_at: Instant::now() + SESSION_TTL,
        },
    );

    let mut response = response_with_cookie(
        Redirect::to(&next_path),
        build_session_cookie(&state, &session_id, SESSION_TTL.as_secs()),
    );

    // If register has an auth signing key, also issue a domain-scoped dd_auth JWT.
    if let Some(ref signing_key) = state.auth_signing_key {
        // Fetch GitHub user info for the JWT claims
        let login = match http
            .get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {token}"))
            .header("User-Agent", "dd-agent")
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
            iss: state.auth_issuer.clone().unwrap_or_default(),
            iat: now,
            exp: now + AUTH_TOKEN_TTL.as_secs() as i64,
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        if let Ok(jwt) = jsonwebtoken::encode(&header, &claims, signing_key) {
            let domain = state
                .cf_config
                .as_ref()
                .map(|c| c.domain.as_str())
                .unwrap_or("devopsdefender.com");
            let cookie = format!(
                "{AUTH_COOKIE}={jwt}; Path=/; Domain=.{domain}; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
                AUTH_TOKEN_TTL.as_secs()
            );
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                response.headers_mut().append(SET_COOKIE, value);
            }
        }
    }

    Ok(response)
}

async fn github_auth_logout(State(state): State<AgentState>, headers: HeaderMap) -> Response {
    if let Some(session_id) = extract_cookie(&headers, SESSION_COOKIE) {
        state.browser_sessions.lock().await.remove(&session_id);
    }

    response_with_cookie(
        Redirect::to("/logged-out"),
        build_session_cookie(&state, "", 0),
    )
}

// ── Password auth ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct LoginQuery {
    next: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    password: String,
    next: Option<String>,
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

async fn login_page(
    State(state): State<AgentState>,
    query: axum::extract::Query<LoginQuery>,
) -> Html<String> {
    let hostname = std::env::var("DD_HOSTNAME").unwrap_or_else(|_| state.vm_name.clone());
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

async fn login_submit(
    State(state): State<AgentState>,
    axum::extract::Form(form): axum::extract::Form<LoginForm>,
) -> Response {
    let expected = match &state.auth_mode {
        AuthMode::Password { ref password, .. } => password.as_bytes(),
        _ => return AppError::Config("Password auth not configured".into()).into_response(),
    };

    let next = sanitize_next_path(form.next.as_deref());

    if !constant_time_eq(form.password.as_bytes(), expected) {
        let mut url = reqwest::Url::parse("http://localhost/auth/login").unwrap();
        url.query_pairs_mut()
            .append_pair("error", "invalid")
            .append_pair("next", &next);
        let location = format!("{}?{}", url.path(), url.query().unwrap_or_default());
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

// ── GitHub token verification ────────────────────────────────────────────

async fn verify_github_token(token: &str, owner: &str) -> Result<(), AppError> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "dd-agent")
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
        .header("User-Agent", "dd-agent")
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

async fn handle_ws_session(socket: WebSocket, state: AgentState, app_name: String) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    let attestation_msg = serde_json::json!({
        "type": "attestation",
        "attestation_type": state.attestation_type,
        "vm_name": state.vm_name,
        "owner": state.owner,
    });
    let _ = ws_tx
        .send(Message::Text(attestation_msg.to_string().into()))
        .await;

    // Check if the process exists
    let exists = {
        let deps = state.deployments.lock().await;
        deps.values()
            .any(|d| d.app_name == app_name && d.status == "running")
    };
    if !exists {
        let err = serde_json::json!({
            "type": "error",
            "message": format!("no running job named '{app_name}'")
        });
        let _ = ws_tx.send(Message::Text(err.to_string().into())).await;
        return;
    }

    // Subscribe to stdout broadcast
    let mut stdout_rx = {
        let handles = state.process_handles.lock().await;
        match handles.get(&app_name) {
            Some(io) => io.stdout_tx.subscribe(),
            None => {
                let err =
                    serde_json::json!({ "type": "error", "message": "process I/O not available" });
                let _ = ws_tx.send(Message::Text(err.to_string().into())).await;
                return;
            }
        }
    };

    let ok = serde_json::json!({
        "type": "ok",
        "status": format!("attached to {app_name}"),
        "attestation_type": state.attestation_type,
    });
    let _ = ws_tx.send(Message::Text(ok.to_string().into())).await;

    // Bidirectional: process stdout → WebSocket, WebSocket → process stdin
    loop {
        tokio::select! {
            result = stdout_rx.recv() => {
                match result {
                    Ok(data) => {
                        let text = String::from_utf8_lossy(&data);
                        let msg = serde_json::json!({ "type": "stdout", "data": text });
                        if ws_tx.send(Message::Text(msg.to_string().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                            if parsed["type"] == "stdin" {
                                if let Some(data) = parsed["data"].as_array() {
                                    let bytes: Vec<u8> = data.iter()
                                        .filter_map(|v| v.as_u64().map(|b| b as u8))
                                        .collect();
                                    let mut handles = state.process_handles.lock().await;
                                    if let Some(io) = handles.get_mut(&app_name) {
                                        use tokio::io::AsyncWriteExt;
                                        let _ = io.stdin.write_all(&bytes).await;
                                        let _ = io.stdin.flush().await;
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

// ── Noise-encrypted WebSocket ────────────────────────────────────────────

async fn ws_noise_session(
    State(state): State<AgentState>,
    Path(app_name): Path<String>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_noise_session(socket, state, app_name))
}

async fn handle_ws_noise_session(socket: WebSocket, state: AgentState, app_name: String) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let attestation_backend = dd_agent::attestation::detect();

    let keypair = match dd_agent::noise::generate_keypair() {
        Ok(k) => k,
        Err(_) => return,
    };

    let mut noise = match snow::Builder::new(dd_agent::noise::NOISE_PATTERN.parse().unwrap())
        .local_private_key(&keypair.private)
        .and_then(|b| b.build_responder())
    {
        Ok(n) => n,
        Err(_) => return,
    };

    let mut buf = vec![0u8; 65535];

    // XX handshake over WebSocket binary frames
    let msg1 = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        _ => return,
    };
    if noise.read_message(&msg1, &mut buf).is_err() {
        return;
    }

    let attestation = dd_agent::noise::build_attestation_payload(
        &state.vm_name,
        Some(&state.owner),
        attestation_backend.as_ref(),
        &keypair.public,
    );
    let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
    let mut msg2_buf = vec![0u8; 65535];
    let msg2_len = match noise.write_message(&attestation_bytes, &mut msg2_buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    if ws_tx
        .send(Message::Binary(msg2_buf[..msg2_len].to_vec().into()))
        .await
        .is_err()
    {
        return;
    }

    let msg3 = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        _ => return,
    };
    let payload_len = match noise.read_message(&msg3, &mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let initiator_attestation: dd_agent::noise::AttestationPayload =
        match serde_json::from_slice(&buf[..payload_len]) {
            Ok(a) => a,
            Err(_) => return,
        };
    let remote_static = match noise.get_remote_static() {
        Some(key) => key,
        None => return,
    };
    if dd_agent::noise::verify_remote_attestation(&initiator_attestation, remote_static).is_err() {
        return;
    }

    let mut transport = match noise.into_transport_mode() {
        Ok(t) => t,
        Err(_) => return,
    };

    // Find process
    let pid = {
        let deps = state.deployments.lock().await;
        deps.values()
            .find(|d| d.app_name == app_name && d.status == "running")
            .and_then(|d| d.pid)
    };

    let pid = match pid {
        Some(p) => p,
        None => {
            let err = serde_json::json!({ "type": "error", "message": format!("no running job '{app_name}'") });
            let err_bytes = serde_json::to_vec(&err).unwrap();
            let mut enc = vec![0u8; 65535];
            if let Ok(len) = transport.write_message(&err_bytes, &mut enc) {
                let _ = ws_tx
                    .send(Message::Binary(enc[..len].to_vec().into()))
                    .await;
            }
            return;
        }
    };

    let ok = serde_json::json!({ "type": "ok", "status": format!("attached to {app_name} (pid {pid})") });
    let ok_bytes = serde_json::to_vec(&ok).unwrap();
    let mut enc = vec![0u8; 65535];
    if let Ok(len) = transport.write_message(&ok_bytes, &mut enc) {
        let _ = ws_tx
            .send(Message::Binary(enc[..len].to_vec().into()))
            .await;
    }

    // Stream log output encrypted
    let log_path = format!("/var/lib/dd/workloads/logs/{pid}.log");
    let log_file = match tokio::fs::File::open(&log_path).await {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut reader = BufReader::new(log_file).lines();

    loop {
        tokio::select! {
            line = reader.next_line() => {
                match line {
                    Ok(Some(text)) => {
                        let msg = serde_json::json!({ "type": "stdout", "data": format!("{text}\n") });
                        let msg_bytes = serde_json::to_vec(&msg).unwrap();
                        let mut enc_buf = vec![0u8; 65535];
                        if let Ok(len) = transport.write_message(&msg_bytes, &mut enc_buf) {
                            if ws_tx.send(Message::Binary(enc_buf[..len].to_vec().into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    Err(_) => break,
                }
            }
            Some(Ok(ws_msg)) = ws_rx.next() => {
                match ws_msg {
                    Message::Binary(data) => {
                        let mut dec_buf = vec![0u8; 65535];
                        if let Ok(len) = transport.read_message(&data, &mut dec_buf) {
                            // Handle stdin if needed
                            let _ = &dec_buf[..len];
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }
}

// ── Noise command channel over WebSocket ──────────────────────────────────

async fn ws_noise_cmd(State(state): State<AgentState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_noise_cmd(socket, state))
}

async fn handle_ws_noise_cmd(socket: WebSocket, state: AgentState) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let attestation_backend = dd_agent::attestation::detect();

    // Noise_XX handshake over WebSocket binary frames
    let keypair = match dd_agent::noise::generate_keypair() {
        Ok(k) => k,
        Err(_) => return,
    };

    let mut noise = match snow::Builder::new(dd_agent::noise::NOISE_PATTERN.parse().unwrap())
        .local_private_key(&keypair.private)
        .and_then(|b| b.build_responder())
    {
        Ok(n) => n,
        Err(_) => return,
    };

    let mut buf = vec![0u8; 65535];

    // msg1
    let msg1 = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        _ => return,
    };
    if noise.read_message(&msg1, &mut buf).is_err() {
        return;
    }

    // msg2 with attestation
    let attestation = dd_agent::noise::build_attestation_payload(
        &state.vm_name,
        Some(&state.owner),
        attestation_backend.as_ref(),
        &keypair.public,
    );
    let att_bytes = serde_json::to_vec(&attestation).unwrap();
    let mut msg2_buf = vec![0u8; 65535];
    let msg2_len = match noise.write_message(&att_bytes, &mut msg2_buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    if ws_tx
        .send(Message::Binary(msg2_buf[..msg2_len].to_vec().into()))
        .await
        .is_err()
    {
        return;
    }

    // msg3
    let msg3 = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        _ => return,
    };
    let payload_len = match noise.read_message(&msg3, &mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let initiator_attestation: dd_agent::noise::AttestationPayload =
        match serde_json::from_slice(&buf[..payload_len]) {
            Ok(a) => a,
            Err(_) => return,
        };
    let remote_static = match noise.get_remote_static() {
        Some(key) => key,
        None => return,
    };
    if dd_agent::noise::verify_remote_attestation(&initiator_attestation, remote_static).is_err() {
        return;
    }

    let mut transport = match noise.into_transport_mode() {
        Ok(t) => t,
        Err(_) => return,
    };

    eprintln!("dd-agent: Noise WebSocket command session established");

    // Session loop — same protocol as the TCP Noise server
    let (container_tx, mut container_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let mut fg_task: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        tokio::select! {
            // Foreground output → encrypt → send to client
            Some(data) = container_rx.recv() => {
                let msg = dd_agent::noise::NoiseMessage::Stdout { data };
                let json = serde_json::to_vec(&msg).unwrap();
                let mut enc = vec![0u8; 65535];
                if let Ok(len) = transport.write_message(&json, &mut enc) {
                    if ws_tx.send(Message::Binary(enc[..len].to_vec().into())).await.is_err() {
                        break;
                    }
                }
            }
            // Client message → decrypt → handle
            msg = ws_rx.next() => {
                let data = match msg {
                    Some(Ok(Message::Binary(data))) => data.to_vec(),
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => continue,
                };

                let mut dec = vec![0u8; 65535];
                let len = match transport.read_message(&data, &mut dec) {
                    Ok(n) => n,
                    Err(_) => break,
                };

                let noise_msg: dd_agent::noise::NoiseMessage = match serde_json::from_slice(&dec[..len]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let response = match noise_msg {
                    dd_agent::noise::NoiseMessage::Deploy { cmd, image, app_name, env, tty } => {
                        let req = DeployRequest {
                            cmd, image, env,
                            app_name: app_name.clone(),
                            volumes: None, tty,
                            post_deploy: None,
                        };
                        let (id, status) = execute_deploy(&state.deployments, req).await;
                        dd_agent::noise::NoiseMessage::Ok {
                            id: Some(id), status: Some(status), message: app_name,
                        }
                    }
                    dd_agent::noise::NoiseMessage::Stop { id } => {
                        match execute_stop(&state.deployments, &id).await {
                            Ok(()) => dd_agent::noise::NoiseMessage::Ok {
                                id: Some(id), status: Some("stopped".into()), message: None,
                            },
                            Err(e) => dd_agent::noise::NoiseMessage::Error { message: e },
                        }
                    }
                    dd_agent::noise::NoiseMessage::Jobs => {
                        let deps = state.deployments.lock().await;
                        let jobs: Vec<dd_agent::noise::JobInfo> = deps.values().map(|d| dd_agent::noise::JobInfo {
                            id: d.id.clone(),
                            app_name: d.app_name.clone(),
                            image: d.image.clone(),
                            status: d.status.clone(),
                            tty: false,
                        }).collect();
                        dd_agent::noise::NoiseMessage::JobList { jobs }
                    }
                    dd_agent::noise::NoiseMessage::Fg { id } => {
                        if let Some(task) = fg_task.take() {
                            task.abort();
                        }
                        let pid = {
                            let deps = state.deployments.lock().await;
                            deps.get(&id).and_then(|d| d.pid)
                        };
                        match pid {
                            Some(pid) => {
                                let log_path = format!("/var/lib/dd/workloads/logs/{pid}.log");
                                match tokio::fs::File::open(&log_path).await {
                                    Ok(file) => {
                                        let tx = container_tx.clone();
                                        fg_task = Some(tokio::spawn(async move {
                                            let mut reader = BufReader::new(file).lines();
                                            loop {
                                                match reader.next_line().await {
                                                    Ok(Some(line)) => {
                                                        if tx.send(format!("{line}\n").into_bytes()).await.is_err() { break; }
                                                    }
                                                    Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                                                    Err(_) => break,
                                                }
                                            }
                                        }));
                                        dd_agent::noise::NoiseMessage::Ok { id: Some(id), status: Some("attached".into()), message: None }
                                    }
                                    Err(e) => dd_agent::noise::NoiseMessage::Error { message: format!("open log: {e}") },
                                }
                            }
                            None => dd_agent::noise::NoiseMessage::Error { message: "job not found".into() },
                        }
                    }
                    dd_agent::noise::NoiseMessage::Bg => {
                        if let Some(task) = fg_task.take() { task.abort(); }
                        dd_agent::noise::NoiseMessage::Ok { id: None, status: Some("detached".into()), message: None }
                    }
                    dd_agent::noise::NoiseMessage::Logs { id } => {
                        let pid = {
                            let deps = state.deployments.lock().await;
                            deps.get(&id).and_then(|d| d.pid)
                        };
                        match pid {
                            Some(pid) => {
                                let log_path = format!("/var/lib/dd/workloads/logs/{pid}.log");
                                let content = tokio::fs::read_to_string(&log_path).await.unwrap_or_default();
                                let tail: String = content.lines().rev().take(50).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
                                dd_agent::noise::NoiseMessage::Stdout { data: tail.into_bytes() }
                            }
                            None => dd_agent::noise::NoiseMessage::Error { message: "job not found".into() },
                        }
                    }
                    dd_agent::noise::NoiseMessage::Exit => break,
                    _ => dd_agent::noise::NoiseMessage::Error { message: "unexpected message".into() },
                };

                let json = serde_json::to_vec(&response).unwrap();
                let mut enc = vec![0u8; 65535];
                if let Ok(len) = transport.write_message(&json, &mut enc) {
                    if ws_tx.send(Message::Binary(enc[..len].to_vec().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    if let Some(task) = fg_task {
        task.abort();
    }
}

// ── HTTP Router ──────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct DashQuery {
    token: Option<String>,
}

async fn dashboard(
    State(state): State<AgentState>,
    query: axum::extract::Query<DashQuery>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, AppError> {
    if !state.owner.is_empty() {
        match require_browser_token(&state, &headers, query.token.as_deref(), &uri).await {
            Ok(_) => {}
            Err(response) => return Ok(response),
        }
    }

    let metrics = collect_metrics().await;
    let deps = state.deployments.lock().await;
    let mut rows = String::new();
    for d in deps.values() {
        let status_class = match d.status.as_str() {
            "running" => "running",
            "deploying" => "deploying",
            "failed" | "exited" => "failed",
            _ => "idle",
        };
        let terminal_link = if d.status == "running" {
            format!(
                r#"<a href="/session/{name}">open session</a>"#,
                name = d.app_name
            )
        } else {
            r#"<span class="dim">—</span>"#.to_string()
        };
        rows.push_str(&format!(
            r#"<tr>
                <td><a href="/workload/{id}">{name}</a></td>
                <td><span class="pill {status_class}">{status}</span></td>
                <td class="dim">{image}</td>
                <td>{started}</td>
                <td>{terminal_link}</td>
            </tr>"#,
            id = d.id,
            name = d.app_name,
            status = d.status,
            image = d.image,
            started = d.started_at.split('T').next().unwrap_or(&d.started_at),
        ));
    }

    let uptime_str = format_uptime(state.started_at.elapsed().as_secs());

    let nav = nav_bar_with_terminal(&[("Dashboard", "/", true)]);
    let hostname = std::env::var("DD_HOSTNAME").unwrap_or_else(|_| state.vm_name.clone());

    let table = if deps.is_empty() {
        r#"<div class="empty">No workloads running</div>"#.to_string()
    } else {
        format!(
            r#"<table><tr><th>app</th><th>status</th><th>image</th><th>started</th><th>session</th></tr>{rows}</table>"#
        )
    };

    let content = format!(
        r#"<h1>{hostname}</h1>
<div class="sub">{agent_id} &middot; {att}</div>
<div class="meta"><span class="ok">healthy</span> &middot; uptime {uptime} &middot; {count} workload(s)</div>

<div class="cards">
  <div class="card"><div class="label">CPU</div><div class="value green">{cpu}%</div></div>
  <div class="card"><div class="label">Memory</div><div class="value blue">{mem_used} / {mem_total}</div></div>
  <div class="card"><div class="label">Disk</div><div class="value peach">{disk_used} / {disk_total}</div></div>
  <div class="card"><div class="label">Load</div><div class="value mauve">{load}</div></div>
</div>

<div class="section">Workloads</div>
{table}"#,
        hostname = hostname,
        agent_id = &state.agent_id[..8.min(state.agent_id.len())],
        att = state.attestation_type,
        uptime = uptime_str,
        count = deps.len(),
        cpu = metrics.cpu_pct,
        mem_used = metrics.mem_used,
        mem_total = metrics.mem_total,
        disk_used = metrics.disk_used,
        disk_total = metrics.disk_total,
        load = metrics.load_1m,
        table = table,
    );

    Ok(Html(page_shell(
        &format!("DD — {}", state.vm_name),
        &nav,
        &content,
    ))
    .into_response())
}

// ── System Metrics ───────────────────────────────────────────────────────

struct SystemMetrics {
    cpu_pct: u64,
    mem_used: String,
    mem_total: String,
    mem_pct: u64,
    disk_used: String,
    disk_total: String,
    disk_pct: u64,
    load_1m: String,
    load_pct: u64,
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1}G", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.0}M", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.0}K", bytes as f64 / 1024.0)
    }
}

async fn collect_metrics() -> SystemMetrics {
    let mut metrics = SystemMetrics {
        cpu_pct: 0,
        mem_used: "?".into(),
        mem_total: "?".into(),
        mem_pct: 0,
        disk_used: "?".into(),
        disk_total: "?".into(),
        disk_pct: 0,
        load_1m: "?".into(),
        load_pct: 0,
    };

    // Memory from /proc/meminfo
    if let Ok(meminfo) = tokio::fs::read_to_string("/proc/meminfo").await {
        let mut total_kb = 0u64;
        let mut available_kb = 0u64;
        for line in meminfo.lines() {
            if let Some(val) = line.strip_prefix("MemTotal:") {
                total_kb = val
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            }
            if let Some(val) = line.strip_prefix("MemAvailable:") {
                available_kb = val
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            }
        }
        if total_kb > 0 {
            let used_kb = total_kb.saturating_sub(available_kb);
            metrics.mem_total = format_bytes(total_kb * 1024);
            metrics.mem_used = format_bytes(used_kb * 1024);
            metrics.mem_pct = (used_kb * 100) / total_kb;
        }
    }

    // Load average from /proc/loadavg
    if let Ok(loadavg) = tokio::fs::read_to_string("/proc/loadavg").await {
        if let Some(load_1m) = loadavg.split_whitespace().next() {
            metrics.load_1m = load_1m.to_string();
            let load: f64 = load_1m.parse().unwrap_or(0.0);
            // Normalize to percentage of CPU count
            let cpus = num_cpus().await;
            metrics.load_pct = ((load / cpus as f64) * 100.0).min(100.0) as u64;
        }
    }

    // CPU usage from /proc/stat (simple: 100 - idle%)
    if let Ok(stat) = tokio::fs::read_to_string("/proc/stat").await {
        if let Some(cpu_line) = stat.lines().next() {
            let vals: Vec<u64> = cpu_line
                .split_whitespace()
                .skip(1)
                .filter_map(|v| v.parse().ok())
                .collect();
            if vals.len() >= 4 {
                let total: u64 = vals.iter().sum();
                let idle = vals[3];
                if total > 0 {
                    metrics.cpu_pct = 100u64.saturating_sub((idle * 100) / total);
                }
            }
        }
    }

    // Disk from /proc/mounts + statvfs equivalent
    if let Ok(output) = tokio::process::Command::new("df")
        .arg("-B1")
        .arg("/")
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout.lines().nth(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let total: u64 = parts[1].parse().unwrap_or(0);
                let used: u64 = parts[2].parse().unwrap_or(0);
                if total > 0 {
                    metrics.disk_total = format_bytes(total);
                    metrics.disk_used = format_bytes(used);
                    metrics.disk_pct = (used * 100) / total;
                }
            }
        }
    }

    metrics
}

/// Public metrics for self-update in register mode.
pub struct SimpleMetrics {
    pub cpu_pct: u64,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
}

pub async fn collect_system_metrics() -> SimpleMetrics {
    let m = collect_metrics().await;
    SimpleMetrics {
        cpu_pct: m.cpu_pct,
        mem_used_mb: parse_size_mb(&m.mem_used),
        mem_total_mb: parse_size_mb(&m.mem_total),
    }
}

async fn num_cpus() -> usize {
    tokio::fs::read_to_string("/proc/cpuinfo")
        .await
        .map(|s| s.matches("processor").count())
        .unwrap_or(1)
}

pub fn build_router(state: AgentState) -> Router {
    let mut router: Router<AgentState> = Router::new();
    let browser_ui = browser_ui_enabled(&state);

    if state.register_mode {
        router = register::add_routes(router);
    } else if browser_ui {
        router = router.route("/", get(dashboard));
    }

    if browser_ui {
        // Auth routes — password login is always available, GitHub only when configured
        router = router
            .route("/auth/login", get(login_page).post(login_submit))
            .route("/auth/logout", get(github_auth_logout))
            .route("/logged-out", get(logged_out_page))
            .route("/workload/{id}", get(workload_page))
            .route("/session/{app_name}", get(session_page))
            .route("/ws/session/{app_name}", get(ws_session));

        if matches!(state.auth_mode, AuthMode::GitHub(_)) {
            router = router
                .route("/auth/github/start", get(github_auth_start))
                .route("/auth/github/callback", get(github_auth_callback));
        }
    }

    let router = router
        .route("/health", get(health))
        .route("/deployments", get(list_deployments))
        .route("/deployments/{id}", get(get_deployment))
        .route("/deployments/{id}/logs", get(deployment_logs))
        .route("/noise/session/{app_name}", get(ws_noise_session))
        .route("/noise/cmd", get(ws_noise_cmd));

    deploy::add_routes(router, browser_ui).with_state(state)
}
