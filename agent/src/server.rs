use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
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

/// Per-process I/O handles for interactive sessions.
pub struct ProcessIO {
    pub stdin: tokio::process::ChildStdin,
    pub stdout_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
}

pub type ProcessHandles = Arc<Mutex<HashMap<String, ProcessIO>>>;

#[derive(Clone)]
pub struct AgentState {
    pub owner: String,
    pub vm_name: String,
    pub agent_id: String,
    pub attestation_type: String,
    pub deployments: Deployments,
    pub process_handles: ProcessHandles,
    pub started_at: std::time::Instant,
}

// ── Auth ──────────────────────────────────────────────────────────────────

fn extract_auth(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or(value.strip_prefix("bearer "))?;
    Some(token.to_string())
}

async fn verify_owner(state: &AgentState, headers: &HeaderMap) -> Result<(), AppError> {
    if state.owner.is_empty() {
        return Ok(());
    }
    let token = extract_auth(headers).ok_or(AppError::Unauthorized)?;
    verify_github_token(&token, &state.owner).await
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

async fn session_page(Path(app_name): Path<String>) -> Html<String> {
    let html = include_str!("../web/terminal.html");
    Html(html.replace("DD Terminal", &format!("DD — {app_name}")))
}

#[derive(Debug, serde::Deserialize)]
struct SessionQuery {
    token: Option<String>,
}

async fn ws_session(
    State(state): State<AgentState>,
    Path(app_name): Path<String>,
    query: axum::extract::Query<SessionQuery>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    // Verify GitHub token if owner is set
    if !state.owner.is_empty() {
        let token = query.token.as_deref().ok_or(AppError::Unauthorized)?;
        verify_github_token(token, &state.owner).await?;
    }
    Ok(ws.on_upgrade(move |socket| handle_ws_session(socket, state, app_name)))
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
) -> Result<Html<String>, AppError> {
    if !state.owner.is_empty() {
        let token = query.token.as_deref().ok_or(AppError::Unauthorized)?;
        verify_github_token(token, &state.owner).await?;
    }

    let metrics = collect_metrics().await;
    let deps = state.deployments.lock().await;
    let mut rows = String::new();
    for d in deps.values() {
        let status_color = match d.status.as_str() {
            "running" => "#a6e3a1",
            "deploying" => "#f9e2af",
            "failed" | "exited" => "#f38ba8",
            _ => "#a6adc8",
        };
        let terminal_link = if d.status == "running" {
            format!(r#"<a href="/session/{}">terminal</a>"#, d.app_name)
        } else {
            String::new()
        };
        rows.push_str(&format!(
            r#"<tr>
                <td>{}</td>
                <td><span style="color:{status_color}">{}</span></td>
                <td>{}</td>
                <td>{}</td>
                <td>{terminal_link}</td>
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
<title>DD — {vm_name}</title>
<style>
  body {{ margin: 0; background: #1e1e2e; color: #cdd6f4; font-family: 'JetBrains Mono', monospace; padding: 24px; }}
  h1 {{ color: #89b4fa; margin: 0 0 4px; font-size: 20px; }}
  .subtitle {{ color: #585b70; font-size: 12px; margin-bottom: 16px; }}
  .meta {{ color: #a6adc8; font-size: 13px; margin-bottom: 20px; }}
  .meta .ok {{ color: #a6e3a1; }}
  .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }}
  .metric {{ background: #313244; border-radius: 8px; padding: 12px 16px; }}
  .metric .label {{ color: #a6adc8; font-size: 11px; text-transform: uppercase; }}
  .metric .value {{ color: #cdd6f4; font-size: 18px; font-weight: bold; margin-top: 4px; }}
  .metric .bar {{ background: #45475a; border-radius: 4px; height: 4px; margin-top: 8px; }}
  .metric .bar-fill {{ background: #89b4fa; border-radius: 4px; height: 4px; }}
  .section {{ color: #a6adc8; font-size: 12px; text-transform: uppercase; margin: 20px 0 8px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th {{ text-align: left; color: #a6adc8; font-weight: normal; font-size: 12px; text-transform: uppercase; padding: 8px 12px; border-bottom: 1px solid #313244; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #313244; font-size: 14px; }}
  a {{ color: #89b4fa; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .empty {{ color: #585b70; padding: 24px; text-align: center; }}
</style>
</head>
<body>
<h1>DevOps Defender</h1>
<div class="subtitle">{agent_id}</div>
<div class="meta">
  {vm_name} &middot; <span class="ok">healthy</span> &middot; {att} &middot; owner: {owner} &middot; uptime {uptime}
</div>

<div class="metrics">
  <div class="metric">
    <div class="label">CPU</div>
    <div class="value">{cpu_pct}%</div>
    <div class="bar"><div class="bar-fill" style="width:{cpu_pct}%"></div></div>
  </div>
  <div class="metric">
    <div class="label">Memory</div>
    <div class="value">{mem_used} / {mem_total}</div>
    <div class="bar"><div class="bar-fill" style="width:{mem_pct}%"></div></div>
  </div>
  <div class="metric">
    <div class="label">Disk</div>
    <div class="value">{disk_used} / {disk_total}</div>
    <div class="bar"><div class="bar-fill" style="width:{disk_pct}%"></div></div>
  </div>
  <div class="metric">
    <div class="label">Load</div>
    <div class="value">{load_1m}</div>
    <div class="bar"><div class="bar-fill" style="width:{load_pct}%"></div></div>
  </div>
</div>

<div class="section">Jobs ({count})</div>
{table}
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
        mem_pct = metrics.mem_pct,
        disk_used = metrics.disk_used,
        disk_total = metrics.disk_total,
        disk_pct = metrics.disk_pct,
        load_1m = metrics.load_1m,
        load_pct = metrics.load_pct,
        table = if deps.is_empty() {
            r#"<div class="empty">no jobs running &mdash; deploy something with <code>dd deploy</code></div>"#.to_string()
        } else {
            format!(
                r#"<table>
<tr><th>app</th><th>status</th><th>image</th><th>started</th><th></th></tr>
{rows}
</table>"#
            )
        },
    )))
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
