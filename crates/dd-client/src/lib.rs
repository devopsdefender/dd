//! dd-client — agent web UI running inside an easyenclave TDX VM.
//!
//! Talks to easyenclave via unix socket, serves a web dashboard + terminal,
//! and optionally registers with dd-register via Noise WS.

pub mod auth;
pub mod config;
pub mod dashboard;
pub mod terminal;

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use dd_common::ee_client::EeClient;
use dd_common::error::AppError;

use crate::auth::BrowserSessions;
use crate::config::Config;

// ── AppState ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub ee_client: Arc<EeClient>,
    pub started_at: std::time::Instant,
    pub auth_public_key: Option<jsonwebtoken::DecodingKey>,
    pub auth_issuer: Option<String>,
    pub browser_sessions: BrowserSessions,
}

// ── Health response ─────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct HealthResponse {
    ok: bool,
    vm_name: String,
    hostname: String,
    owner: String,
    attestation_type: String,
    workload_count: usize,
    uptime_seconds: u64,
    ee_uptime_seconds: u64,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let ee_health = state.ee_client.health().await.unwrap_or_default();
    let att = ee_health["attestation_type"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let workloads = ee_health["workloads"].as_u64().unwrap_or(0) as usize;
    let ee_uptime = ee_health["uptime_secs"].as_u64().unwrap_or(0);

    Json(HealthResponse {
        ok: true,
        vm_name: state.config.vm_name.clone(),
        hostname: state
            .config
            .hostname
            .clone()
            .unwrap_or_else(|| state.config.vm_name.clone()),
        owner: state.config.owner.clone(),
        attestation_type: att,
        workload_count: workloads,
        uptime_seconds: state.started_at.elapsed().as_secs(),
        ee_uptime_seconds: ee_uptime,
    })
}

// ── API proxy handlers ──────────────────────────────────────────────────

async fn list_deployments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    auth::verify_owner(&state, &headers).await?;
    let resp = state.ee_client.list().await.map_err(AppError::External)?;
    Ok(Json(resp).into_response())
}

async fn deployment_logs(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    auth::verify_owner(&state, &headers).await?;
    let resp = state
        .ee_client
        .logs(&id)
        .await
        .map_err(AppError::External)?;
    Ok(Json(resp).into_response())
}

async fn post_deploy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    auth::verify_owner(&state, &headers).await?;
    let resp = state
        .ee_client
        .deploy(req)
        .await
        .map_err(AppError::External)?;
    Ok(Json(resp).into_response())
}

async fn post_exec(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    auth::verify_owner(&state, &headers).await?;
    let cmd: Vec<String> = req["cmd"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if cmd.is_empty() {
        return Err(AppError::InvalidInput("cmd must not be empty".into()));
    }
    let timeout = req["timeout_secs"].as_u64().unwrap_or(30);
    let resp = state
        .ee_client
        .exec(&cmd, timeout)
        .await
        .map_err(AppError::External)?;
    Ok(Json(resp).into_response())
}

// ── Route: /re-register (POST) ──────────────────────────────────────────
// Triggers re-registration with dd-register. Used by the collector to
// migrate agents to a new register instance after a zero-downtime deploy.

async fn post_re_register(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    auth::verify_owner(&state, &headers).await?;

    let register_url = state
        .config
        .register_url
        .as_deref()
        .ok_or_else(|| AppError::InvalidInput("no register URL configured".into()))?;

    eprintln!("dd-client: re-registering with {register_url}");
    match register_with_noise(
        register_url,
        &state.config.vm_name,
        &state.config.owner,
        &state.ee_client,
    )
    .await
    {
        Ok(bootstrap) => {
            eprintln!("dd-client: re-registered — hostname={}", bootstrap.hostname);

            // Start new cloudflared if tunnel token changed.
            if let Err(e) = start_cloudflared(&bootstrap.tunnel_token).await {
                eprintln!("dd-client: cloudflared restart failed: {e}");
            }

            Ok(Json(serde_json::json!({
                "ok": true,
                "hostname": bootstrap.hostname,
            }))
            .into_response())
        }
        Err(e) => {
            eprintln!("dd-client: re-registration failed: {e}");
            Err(AppError::External(e))
        }
    }
}

// ── Registration via Noise WS ───────────────────────────────────────────

async fn register_with_noise(
    register_url: &str,
    vm_name: &str,
    owner: &str,
    ee_client: &EeClient,
) -> Result<dd_common::noise::BootstrapConfig, String> {
    use futures_util::{SinkExt, StreamExt};

    let keypair = dd_common::noise::generate_keypair()?;

    // Connect via WebSocket
    let (ws_stream, _) = tokio_tungstenite::connect_async(register_url)
        .await
        .map_err(|e| format!("ws connect to {register_url}: {e}"))?;

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    let mut noise = snow::Builder::new(dd_common::noise::NOISE_PATTERN.parse().unwrap())
        .local_private_key(&keypair.private)
        .build_initiator()
        .map_err(|e| format!("build initiator: {e}"))?;

    let mut buf = vec![0u8; 65535];

    // XX handshake over WebSocket binary frames

    // msg1
    let mut msg1_buf = vec![0u8; 65535];
    let msg1_len = noise
        .write_message(&[], &mut msg1_buf)
        .map_err(|e| format!("msg1: {e}"))?;
    ws_tx
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            msg1_buf[..msg1_len].to_vec(),
        ))
        .await
        .map_err(|e| format!("send msg1: {e}"))?;

    // msg2 carries a freshness nonce from the register. Embed it in the
    // TDX quote's REPORT_DATA so ITA can prove the quote was made *for
    // this handshake* and isn't a replay.
    let msg2 = match ws_rx.next().await {
        Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => data.to_vec(),
        other => return Err(format!("expected binary msg2, got: {other:?}")),
    };
    let msg2_payload_len = noise
        .read_message(&msg2, &mut buf)
        .map_err(|e| format!("msg2: {e}"))?;
    let msg2_payload: serde_json::Value = serde_json::from_slice(&buf[..msg2_payload_len])
        .map_err(|e| format!("parse msg2 payload: {e}"))?;
    let nonce_b64 = msg2_payload["nonce"]
        .as_str()
        .ok_or_else(|| "msg2 missing nonce".to_string())?
        .to_string();

    // Ask easyenclave for a quote bound to the nonce. REPORT_DATA in
    // the quote will contain the nonce bytes so the register can bind
    // verification to this handshake.
    let attest_resp = ee_client
        .attest(&nonce_b64)
        .await
        .map_err(|e| format!("ee attest: {e}"))?;
    let tdx_quote_b64 = attest_resp["quote_b64"]
        .as_str()
        .ok_or_else(|| format!("ee attest missing quote_b64: {attest_resp}"))?
        .to_string();

    let attestation = dd_common::noise::AttestationPayload {
        attestation_type: "tdx".into(),
        vm_name: vm_name.into(),
        tdx_quote_b64: Some(tdx_quote_b64),
    };

    // msg3 with attestation
    let attestation_json = serde_json::to_vec(&attestation).unwrap();
    let mut msg3_buf = vec![0u8; 65535];
    let msg3_len = noise
        .write_message(&attestation_json, &mut msg3_buf)
        .map_err(|e| format!("msg3: {e}"))?;
    ws_tx
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            msg3_buf[..msg3_len].to_vec(),
        ))
        .await
        .map_err(|e| format!("send msg3: {e}"))?;

    let mut transport = noise
        .into_transport_mode()
        .map_err(|e| format!("transport: {e}"))?;

    // Send encrypted registration request
    let req = serde_json::json!({ "owner": owner, "vm_name": vm_name });
    let req_json = serde_json::to_vec(&req).unwrap();
    let mut enc_buf = vec![0u8; 65535];
    let enc_len = transport
        .write_message(&req_json, &mut enc_buf)
        .map_err(|e| format!("encrypt: {e}"))?;
    ws_tx
        .send(tokio_tungstenite::tungstenite::Message::Binary(
            enc_buf[..enc_len].to_vec(),
        ))
        .await
        .map_err(|e| format!("send req: {e}"))?;

    // Read encrypted bootstrap config
    let enc_resp = match ws_rx.next().await {
        Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => data.to_vec(),
        other => return Err(format!("expected binary response, got: {other:?}")),
    };
    let resp_len = transport
        .read_message(&enc_resp, &mut buf)
        .map_err(|e| format!("decrypt: {e}"))?;

    serde_json::from_slice(&buf[..resp_len]).map_err(|e| format!("parse config: {e}"))
}

// ── Cloudflared tunnel ──────────────────────────────────────────────────

async fn start_cloudflared(tunnel_token: &str) -> Result<(), String> {
    eprintln!("dd-client: starting cloudflared tunnel");
    let _child = tokio::process::Command::new("cloudflared")
        .args(["tunnel", "--no-autoupdate", "run", "--token", tunnel_token])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn cloudflared: {e}"))?;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    if is_process_running("cloudflared") {
        eprintln!("dd-client: cloudflared running");
        Ok(())
    } else {
        Err("cloudflared not running after spawn".into())
    }
}

fn is_process_running(name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let pid_str = fname.to_string_lossy();
        if pid_str.chars().all(|c| c.is_ascii_digit()) {
            let cmdline_path = format!("/proc/{pid_str}/cmdline");
            if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                if cmdline.contains(name) {
                    return true;
                }
            }
        }
    }
    false
}

// ── Main ────────────────────────────────────────────────────────────────

pub async fn run() {
    let mut config = Config::from_env();
    eprintln!(
        "dd-client: starting — vm={} owner={} port={}",
        config.vm_name, config.owner, config.port
    );

    // Connect to easyenclave socket
    let ee_client = Arc::new(EeClient::new(&config.ee_socket_path));

    // Verify easyenclave is reachable
    match ee_client.health().await {
        Ok(h) => {
            eprintln!(
                "dd-client: easyenclave connected — attestation={}",
                h["attestation_type"].as_str().unwrap_or("unknown")
            );
        }
        Err(e) => {
            eprintln!("dd-client: warning: easyenclave not reachable: {e}");
        }
    }

    // Register with dd-register if configured
    let mut auth_key: Option<jsonwebtoken::DecodingKey> = None;
    let mut auth_issuer: Option<String> = None;

    if let Some(ref register_url) = config.register_url {
        eprintln!("dd-client: registering with {register_url}");
        match register_with_noise(register_url, &config.vm_name, &config.owner, &ee_client).await {
            Ok(bootstrap) => {
                eprintln!(
                    "dd-client: registered — owner={} hostname={}",
                    bootstrap.owner, bootstrap.hostname
                );

                // Update config with registration results
                if config.owner.is_empty() {
                    config.owner = bootstrap.owner.clone();
                }
                config.hostname = Some(bootstrap.hostname.clone());

                // Start cloudflared tunnel
                if let Err(e) = start_cloudflared(&bootstrap.tunnel_token).await {
                    eprintln!("dd-client: cloudflared start failed: {e}");
                }

                // Set up auth keys from register
                if let Some(ref key_b64) = bootstrap.auth_public_key {
                    if let Some(key) = auth::auth_key_from_b64(key_b64) {
                        auth_key = Some(key);
                        auth_issuer.clone_from(&bootstrap.auth_issuer);
                        eprintln!("dd-client: register auth tokens enabled");
                    }
                }
            }
            Err(e) => {
                eprintln!("dd-client: registration failed: {e}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("dd-client: no register URL, running standalone");
    }

    let browser_sessions: BrowserSessions =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let state = AppState {
        config: Arc::new(config),
        ee_client,
        started_at: std::time::Instant::now(),
        auth_public_key: auth_key,
        auth_issuer,
        browser_sessions,
    };

    let port = state.config.port;

    // Build router
    let app = axum::Router::new()
        .route("/", get(dashboard::dashboard))
        .route("/health", get(health))
        .route("/workload/{id}", get(dashboard::workload_page))
        .route("/session/{app_name}", get(terminal::session_page))
        .route("/ws/session/{app_name}", get(terminal::ws_session))
        .route("/deploy", post(post_deploy))
        .route("/exec", post(post_exec))
        .route("/deployments", get(list_deployments))
        .route("/deployments/{id}/logs", get(deployment_logs))
        .route(
            "/auth/login",
            get(auth::login_page).post(auth::login_submit),
        )
        .route("/auth/logout", get(auth::logout))
        .route("/re-register", post(post_re_register))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("dd-client: listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("dd-client: bind failed: {e}");
            std::process::exit(1);
        });

    axum::serve(listener, app).await.unwrap_or_else(|e| {
        eprintln!("dd-client: server error: {e}");
        std::process::exit(1);
    });
}
