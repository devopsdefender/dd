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

use crate::common::error::AppError;

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentInfo {
    pub id: String,
    pub pid: Option<u32>,
    pub app_name: String,
    pub image: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub started_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeployRequest {
    pub image: String,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub app_version: Option<String>,
    #[serde(default)]
    pub tty: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub agent_id: String,
    pub vm_name: String,
    pub owner: String,
    pub attestation_type: String,
    pub deployment_count: usize,
    pub uptime_seconds: u64,
}

pub type Deployments = Arc<Mutex<HashMap<String, DeploymentInfo>>>;
pub type BrowserSessions = Arc<Mutex<HashMap<String, BrowserSession>>>;
pub type PendingOauthStates = Arc<Mutex<HashMap<String, PendingOauthState>>>;

/// Per-process I/O handles for interactive sessions.
pub struct ProcessIO {
    pub stdin: tokio::process::ChildStdin,
    pub stdout_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
}

pub type ProcessHandles = Arc<Mutex<HashMap<String, ProcessIO>>>;

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

#[derive(Clone)]
pub struct AgentState {
    pub owner: String,
    pub vm_name: String,
    pub agent_id: String,
    pub attestation_type: String,
    pub deployments: Deployments,
    pub process_handles: ProcessHandles,
    pub started_at: std::time::Instant,
    pub oauth: Option<GithubOAuthConfig>,
    pub browser_sessions: BrowserSessions,
    pub pending_oauth_states: PendingOauthStates,
}

// ── Auth ──────────────────────────────────────────────────────────────────

const SESSION_COOKIE: &str = "dd_session";
const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);
const OAUTH_STATE_TTL: Duration = Duration::from_secs(10 * 60);

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

fn build_session_cookie(state: &AgentState, session_id: &str, max_age: u64) -> String {
    let mut cookie =
        format!("{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if state
        .oauth
        .as_ref()
        .map(|oauth| oauth.secure_cookies)
        .unwrap_or(false)
    {
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

async fn resolve_github_token(
    state: &AgentState,
    headers: &HeaderMap,
    query_token: Option<&str>,
) -> Result<Option<String>, AppError> {
    if state.owner.is_empty() {
        return Ok(None);
    }

    if let Some(token) = query_token.filter(|token| !token.is_empty()) {
        verify_github_token(token, &state.owner).await?;
        return Ok(Some(token.to_string()));
    }

    if let Some(token) = extract_auth(headers) {
        verify_github_token(&token, &state.owner).await?;
        return Ok(Some(token));
    }

    if let Some(token) = session_token_from_cookie(state, headers).await {
        return Ok(Some(token));
    }

    Err(AppError::Unauthorized)
}

async fn require_browser_token(
    state: &AgentState,
    headers: &HeaderMap,
    query_token: Option<&str>,
    current_uri: &Uri,
) -> Result<Option<String>, Response> {
    match resolve_github_token(state, headers, query_token).await {
        Ok(token) => Ok(token),
        Err(AppError::Unauthorized) if state.oauth.is_some() => {
            Err(github_oauth_redirect(current_uri).into_response())
        }
        Err(err) => Err(err.into_response()),
    }
}

async fn verify_owner(state: &AgentState, headers: &HeaderMap) -> Result<(), AppError> {
    resolve_github_token(state, headers, None).await.map(|_| ())
}

// ── HTTP Handlers (read-only) ────────────────────────────────────────────

async fn health(State(state): State<AgentState>) -> Json<HealthResponse> {
    let deployment_count = state.deployments.lock().await.len();
    Json(HealthResponse {
        ok: true,
        agent_id: state.agent_id.clone(),
        vm_name: state.vm_name.clone(),
        owner: state.owner.clone(),
        attestation_type: state.attestation_type.clone(),
        deployment_count,
        uptime_seconds: state.started_at.elapsed().as_secs(),
    })
}

async fn logged_out_page() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DD — Signed Out</title>
</head>
<body>
<main>
  <h1>Signed out</h1>
  <p>Your browser session has been cleared.</p>
  <p><a href="/">Return to dashboard</a></p>
</main>
</body>
</html>"#,
    )
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
    let pid = {
        let deps = state.deployments.lock().await;
        let info = deps.get(&id).ok_or(AppError::NotFound)?;
        info.pid
    };
    // Read from the process log file
    let logs: Vec<String> = if let Some(pid) = pid {
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

    let html = include_str!("../web/terminal.html");
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
    resolve_github_token(&state, &headers, query.token.as_deref()).await?;
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
    let oauth = state
        .oauth
        .as_ref()
        .ok_or_else(|| AppError::Config("GitHub OAuth is not configured".into()))?;
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

    let oauth = state
        .oauth
        .as_ref()
        .ok_or_else(|| AppError::Config("GitHub OAuth is not configured".into()))?;
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
            token,
            expires_at: Instant::now() + SESSION_TTL,
        },
    );

    Ok(response_with_cookie(
        Redirect::to(&next_path),
        build_session_cookie(&state, &session_id, SESSION_TTL.as_secs()),
    ))
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

    let keypair = match crate::noise::generate_keypair() {
        Ok(k) => k,
        Err(_) => return,
    };

    let mut noise = match snow::Builder::new(crate::noise::NOISE_PATTERN.parse().unwrap())
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

    let attestation = serde_json::json!({
        "attestation_type": state.attestation_type,
        "vm_name": state.vm_name,
        "owner": state.owner,
    });
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
    if noise.read_message(&msg3, &mut buf).is_err() {
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

    // Noise_XX handshake over WebSocket binary frames
    let keypair = match crate::noise::generate_keypair() {
        Ok(k) => k,
        Err(_) => return,
    };

    let mut noise = match snow::Builder::new(crate::noise::NOISE_PATTERN.parse().unwrap())
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
    let attestation = serde_json::json!({
        "attestation_type": state.attestation_type,
        "vm_name": state.vm_name,
        "owner": state.owner,
    });
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
    if noise.read_message(&msg3, &mut buf).is_err() {
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
                let msg = crate::noise::NoiseMessage::Stdout { data };
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

                let noise_msg: crate::noise::NoiseMessage = match serde_json::from_slice(&dec[..len]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let response = match noise_msg {
                    crate::noise::NoiseMessage::Deploy { image, app_name, env, cmd, tty } => {
                        let req = DeployRequest {
                            image, env, cmd,
                            app_name: app_name.clone(),
                            app_version: None, tty,
                        };
                        let (id, status) = execute_deploy(&state.deployments, req).await;
                        crate::noise::NoiseMessage::Ok {
                            id: Some(id), status: Some(status), message: app_name,
                        }
                    }
                    crate::noise::NoiseMessage::Stop { id } => {
                        match execute_stop(&state.deployments, &id).await {
                            Ok(()) => crate::noise::NoiseMessage::Ok {
                                id: Some(id), status: Some("stopped".into()), message: None,
                            },
                            Err(e) => crate::noise::NoiseMessage::Error { message: e },
                        }
                    }
                    crate::noise::NoiseMessage::Jobs => {
                        let deps = state.deployments.lock().await;
                        let jobs: Vec<crate::noise::JobInfo> = deps.values().map(|d| crate::noise::JobInfo {
                            id: d.id.clone(),
                            app_name: d.app_name.clone(),
                            image: d.image.clone(),
                            status: d.status.clone(),
                            tty: false,
                        }).collect();
                        crate::noise::NoiseMessage::JobList { jobs }
                    }
                    crate::noise::NoiseMessage::Fg { id } => {
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
                                        crate::noise::NoiseMessage::Ok { id: Some(id), status: Some("attached".into()), message: None }
                                    }
                                    Err(e) => crate::noise::NoiseMessage::Error { message: format!("open log: {e}") },
                                }
                            }
                            None => crate::noise::NoiseMessage::Error { message: "job not found".into() },
                        }
                    }
                    crate::noise::NoiseMessage::Bg => {
                        if let Some(task) = fg_task.take() { task.abort(); }
                        crate::noise::NoiseMessage::Ok { id: None, status: Some("detached".into()), message: None }
                    }
                    crate::noise::NoiseMessage::Logs { id } => {
                        let pid = {
                            let deps = state.deployments.lock().await;
                            deps.get(&id).and_then(|d| d.pid)
                        };
                        match pid {
                            Some(pid) => {
                                let log_path = format!("/var/lib/dd/workloads/logs/{pid}.log");
                                let content = tokio::fs::read_to_string(&log_path).await.unwrap_or_default();
                                let tail: String = content.lines().rev().take(50).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
                                crate::noise::NoiseMessage::Stdout { data: tail.into_bytes() }
                            }
                            None => crate::noise::NoiseMessage::Error { message: "job not found".into() },
                        }
                    }
                    crate::noise::NoiseMessage::Exit => break,
                    _ => crate::noise::NoiseMessage::Error { message: "unexpected message".into() },
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
    let session_query = query
        .token
        .as_deref()
        .map(|token| format!("?token={token}"))
        .unwrap_or_default();
    for d in deps.values() {
        let status_class = match d.status.as_str() {
            "running" => "running",
            "deploying" => "deploying",
            "failed" | "exited" => "failed",
            _ => "idle",
        };
        let terminal_link = if d.status == "running" {
            format!(
                r#"<a class="action-link" href="/session/{}{}">open session</a>"#,
                d.app_name, session_query
            )
        } else {
            r#"<span class="muted">unavailable</span>"#.to_string()
        };
        rows.push_str(&format!(
            r#"<tr>
                <td data-label="App"><span class="app-name">{}</span></td>
                <td data-label="Status"><span class="status-pill {status_class}">{}</span></td>
                <td data-label="Image"><span class="image-name">{}</span></td>
                <td data-label="Started">{}</td>
                <td data-label="Session" class="actions">{terminal_link}</td>
            </tr>"#,
            d.app_name,
            d.status,
            d.image,
            d.started_at.split('T').next().unwrap_or(&d.started_at),
        ));
    }

    let uptime = state.started_at.elapsed().as_secs();
    let uptime_str = if uptime > 3600 {
        format!("{}h {}m", uptime / 3600, (uptime % 3600) / 60)
    } else if uptime > 60 {
        format!("{}m {}s", uptime / 60, uptime % 60)
    } else {
        format!("{uptime}s")
    };

    Ok(Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DD — {vm_name}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    color: #111827;
    font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #fff;
  }}
  main {{
    width: min(960px, 100%);
    margin: 0 auto;
    padding: 16px;
  }}
  header, section {{
    margin-top: 18px;
  }}
  header {{
    margin-top: 0;
  }}
  h1, h2, p {{
    margin: 0;
  }}
  h1 {{
    font-size: clamp(2rem, 6vw, 2.5rem);
    line-height: 1.1;
  }}
  h2 {{
    font-size: 1rem;
  }}
  p, li, td, th, a, code {{
    font-size: 0.95rem;
    line-height: 1.45;
  }}
  ul {{
    margin: 12px 0 0;
    padding-left: 1.2rem;
  }}
  .muted {{
    color: #4b5563;
  }}
  .metrics {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
    margin-top: 14px;
  }}
  .metric {{
    border: 1px solid #d1d5db;
    padding: 12px;
  }}
  .metric strong {{
    display: block;
    font-size: 1.25rem;
    margin-top: 4px;
  }}
  .status {{
    font-weight: 700;
  }}
  .status.running {{ color: #166534; }}
  .status.deploying {{ color: #92400e; }}
  .status.failed {{ color: #991b1b; }}
  .status.idle {{ color: #4b5563; }}
  .table-wrap {{ overflow-x: auto; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
  }}
  thead {{
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }}
  tbody, tr {{ display: block; }}
  tr {{
    border-top: 1px solid #e5e7eb;
    padding: 10px 0;
  }}
  td {{
    display: grid;
    grid-template-columns: minmax(76px, 90px) minmax(0, 1fr);
    gap: 12px;
    align-items: center;
    padding: 6px 0;
  }}
  td::before {{
    content: attr(data-label);
    color: #4b5563;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
  }}
  .actions {{ align-items: start; }}
  a {{
    color: #1d4ed8;
    text-decoration-thickness: 1px;
  }}
  .empty {{
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid #e5e7eb;
  }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  @media (min-width: 720px) {{
    main {{ padding: 24px; }}
    .metrics {{ grid-template-columns: repeat(4, minmax(0, 1fr)); }}
  }}
  @media (min-width: 840px) {{
    thead {{
      position: static;
      width: auto;
      height: auto;
      margin: 0;
      overflow: visible;
      clip: auto;
      white-space: normal;
    }}
    tbody {{ display: table-row-group; }}
    tr {{
      display: table-row;
      padding: 0;
    }}
    th {{
      padding: 0 0 10px;
      text-align: left;
      color: #4b5563;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      border-bottom: 1px solid #d1d5db;
    }}
    td {{
      display: table-cell;
      padding: 12px 0;
      border-bottom: 1px solid #e5e7eb;
      vertical-align: middle;
    }}
    td::before {{ display: none; }}
    .actions {{ text-align: right; }}
  }}
</style>
</head>
<body>
<main>
  <header>
    <h1>DevOps Defender</h1>
    <p class="muted">{agent_id}</p>
    <p><a href="/auth/logout">Log out</a></p>
    <ul>
      <li>vm: <strong>{vm_name}</strong></li>
      <li>health: <strong>healthy</strong></li>
      <li>attestation: <strong>{att}</strong></li>
      <li>owner: <strong>{owner}</strong></li>
      <li>uptime: <strong>{uptime}</strong></li>
    </ul>
    <div class="metrics">
      <div class="metric">
        <div>CPU</div>
        <strong>{cpu_pct}%</strong>
        <div class="muted">live host utilization</div>
      </div>
      <div class="metric">
        <div>Memory</div>
        <strong>{mem_used}</strong>
        <div class="muted">{mem_used} of {mem_total}</div>
      </div>
      <div class="metric">
        <div>Disk</div>
        <strong>{disk_used}</strong>
        <div class="muted">{disk_used} of {disk_total}</div>
      </div>
      <div class="metric">
        <div>Load</div>
        <strong>{load_1m}</strong>
        <div class="muted">normalized over CPUs</div>
      </div>
    </div>
  </header>

  <section>
    <h2>Jobs ({count})</h2>
    {table}
  </section>
</main>
</body>
</html>"#,
        vm_name = state.vm_name,
        agent_id = state.agent_id,
        att = state.attestation_type,
        owner = state.owner,
        uptime = uptime_str,
        count = deps.len(),
        cpu_pct = metrics.cpu_pct,
        mem_used = metrics.mem_used,
        mem_total = metrics.mem_total,
        disk_used = metrics.disk_used,
        disk_total = metrics.disk_total,
        load_1m = metrics.load_1m,
        table = if deps.is_empty() {
            r#"<div class="empty">no jobs running &mdash; deploy something with <code>dd deploy</code></div>"#.to_string()
        } else {
            format!(
                r#"<div class="table-wrap"><table>
<thead><tr><th>app</th><th>status</th><th>image</th><th>started</th><th>session</th></tr></thead>
<tbody>
{rows}
</tbody>
</table></div>"#
            )
        },
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

async fn num_cpus() -> usize {
    tokio::fs::read_to_string("/proc/cpuinfo")
        .await
        .map(|s| s.matches("processor").count())
        .unwrap_or(1)
}

pub fn build_router(state: AgentState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/logged-out", get(logged_out_page))
        .route("/auth/github/start", get(github_auth_start))
        .route("/auth/github/callback", get(github_auth_callback))
        .route("/auth/logout", get(github_auth_logout))
        .route("/health", get(health))
        .route("/deployments", get(list_deployments))
        .route("/deployments/{id}", get(get_deployment))
        .route("/deployments/{id}/logs", get(deployment_logs))
        .route("/session/{app_name}", get(session_page))
        .route("/ws/session/{app_name}", get(ws_session))
        .route("/noise/session/{app_name}", get(ws_noise_session))
        .route("/noise/cmd", get(ws_noise_cmd))
        .with_state(state)
}

// ── Deploy/Stop logic (called by Noise command channel) ──────────────────

pub async fn execute_deploy(deployments: &Deployments, req: DeployRequest) -> (String, String) {
    let dep_id = uuid::Uuid::new_v4().to_string();
    let app_name = req.app_name.clone().unwrap_or_else(|| "unnamed".into());
    let short_id = dep_id[..8].to_string();

    let info = DeploymentInfo {
        id: dep_id.clone(),
        pid: None,
        app_name: app_name.clone(),
        image: req.image.clone(),
        status: "deploying".into(),
        error_message: None,
        started_at: chrono::Utc::now().to_rfc3339(),
    };
    deployments.lock().await.insert(dep_id.clone(), info);

    let deployments_clone = deployments.clone();
    tokio::spawn(async move {
        run_deploy(deployments_clone, dep_id, app_name, req).await;
    });

    (short_id, "deploying".into())
}

async fn run_deploy(
    deployments: Deployments,
    dep_id: String,
    app_name: String,
    req: DeployRequest,
) {
    // Kill old processes for same app
    {
        let deps = deployments.lock().await;
        let old_pids: Vec<(String, Option<u32>)> = deps
            .values()
            .filter(|d| d.app_name == app_name && d.id != dep_id)
            .map(|d| (d.id.clone(), d.pid))
            .collect();
        drop(deps);
        for (old_id, old_pid) in old_pids {
            if let Some(pid) = old_pid {
                let _ = crate::process::kill_process(pid).await;
            }
            deployments.lock().await.remove(&old_id);
        }
    }

    // Pull image
    let config = match crate::process::pull_image(&req.image, &app_name).await {
        Ok(c) => c,
        Err(e) => {
            set_deploy_failed(&deployments, &dep_id, &e).await;
            return;
        }
    };

    // Spawn process
    let extra_env = req.env.unwrap_or_default();
    match crate::process::spawn_workload(&app_name, &config, extra_env, req.tty).await {
        Ok(child) => {
            let pid = child.id();
            eprintln!("dd-agent: deployment {dep_id} running (pid={pid:?})");
            let mut deps = deployments.lock().await;
            if let Some(info) = deps.get_mut(&dep_id) {
                info.pid = pid;
                info.status = "running".into();
            }
        }
        Err(e) => {
            set_deploy_failed(&deployments, &dep_id, &e).await;
        }
    }
}

async fn set_deploy_failed(deployments: &Deployments, dep_id: &str, error: &str) {
    eprintln!("dd-agent: deployment {dep_id} failed: {error}");
    let mut deps = deployments.lock().await;
    if let Some(info) = deps.get_mut(dep_id) {
        info.status = "failed".into();
        info.error_message = Some(error.to_string());
    }
}

pub async fn execute_stop(deployments: &Deployments, id: &str) -> Result<(), String> {
    let pid = {
        let deps = deployments.lock().await;
        let info = deps.get(id).ok_or("deployment not found")?;
        if info.status != "running" && info.status != "deploying" {
            return Err(format!(
                "cannot stop deployment in '{}' status",
                info.status
            ));
        }
        info.pid
    };

    if let Some(pid) = pid {
        crate::process::kill_process(pid).await?;
    }

    let mut deps = deployments.lock().await;
    if let Some(info) = deps.get_mut(id) {
        info.status = "stopped".into();
    }
    Ok(())
}
