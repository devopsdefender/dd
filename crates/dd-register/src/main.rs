//! dd-register -- minimal tunnel provisioning service.
//!
//! Handles agent registration (Noise XX over WebSocket), CF tunnel lifecycle,
//! and fleet health. No dashboard, no OAuth, no scraping -- those are dd-web's job.

mod handler;

use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use dd_common::tunnel;
use handler::{AgentRegistry, RegisteredAgent};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// ── Shared state ────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    hostname: String,
    registry: AgentRegistry,
    cf: tunnel::CfConfig,
    /// Base64-encoded HMAC secret for agent JWT verification.
    auth_public_key_b64: Option<String>,
    /// Auth issuer URL (https://<hostname>).
    auth_issuer: Option<String>,
}

// ── Entry point ─────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("DD_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let cf = match tunnel::CfConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dd-register: {e}");
            eprintln!(
                "dd-register: set DD_CF_API_TOKEN, DD_CF_ACCOUNT_ID, DD_CF_ZONE_ID, DD_CF_DOMAIN"
            );
            std::process::exit(1);
        }
    };

    let hostname = std::env::var("DD_HOSTNAME").unwrap_or_else(|_| {
        eprintln!("dd-register: DD_HOSTNAME not set");
        std::process::exit(1);
    });

    // Self-register: create our own CF tunnel so we're reachable
    let register_id = uuid::Uuid::new_v4().to_string();
    eprintln!("dd-register: self-registering tunnel for {hostname}");

    let http_client = reqwest::Client::new();
    let tunnel_info = match tunnel::create_agent_tunnel(
        &http_client,
        &cf,
        &register_id,
        "register",
        Some(&hostname),
    )
    .await
    {
        Ok(info) => info,
        Err(e) => {
            eprintln!("dd-register: self-registration failed: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("dd-register: tunnel created -- {}", tunnel_info.hostname);

    // Start cloudflared with the tunnel token
    let token = tunnel_info.tunnel_token.clone();
    tokio::spawn(async move {
        eprintln!("dd-register: starting cloudflared");
        let mut child = tokio::process::Command::new("cloudflared")
            .args(["tunnel", "--no-autoupdate", "run", "--token", &token])
            .spawn()
            .expect("failed to spawn cloudflared");
        let status = child.wait().await;
        eprintln!("dd-register: cloudflared exited: {status:?}");
    });

    // Bootstrap registry from existing CF tunnels
    let registry: AgentRegistry = Arc::new(Mutex::new(HashMap::new()));
    let env_label = std::env::var("DD_ENV").unwrap_or_else(|_| "dev".into());
    let prefix = format!("dd-{env_label}-");

    match tunnel::list_tunnels(&http_client, &cf).await {
        Ok(tunnels) => {
            let mut count = 0usize;
            for t in &tunnels {
                let name = t["name"].as_str().unwrap_or_default();
                let id = t["id"].as_str().unwrap_or_default();
                if !name.starts_with(&prefix) || id.is_empty() {
                    continue;
                }
                // Extract agent_id from tunnel name: dd-<env>-<agent_id>
                let agent_id = name.strip_prefix(&prefix).unwrap_or(name).to_string();
                let tun_hostname = format!("{name}.{}", cf.domain);
                let now = chrono::Utc::now();
                registry.lock().await.insert(
                    agent_id.clone(),
                    RegisteredAgent {
                        agent_id,
                        hostname: tun_hostname,
                        vm_name: String::new(),
                        attestation_type: "unknown".into(),
                        registered_at: now.to_rfc3339(),
                        last_seen: now,
                        status: "discovered".into(),
                    },
                );
                count += 1;
            }
            eprintln!("dd-register: bootstrapped {count} agent(s) from CF tunnels");
        }
        Err(e) => {
            eprintln!("dd-register: tunnel bootstrap failed (non-fatal): {e}");
        }
    }

    // Generate auth signing keypair for JWT issuance
    let (auth_public_key_b64, auth_issuer) = {
        let mut secret = Vec::with_capacity(32);
        secret.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
        secret.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &secret);
        let issuer = format!("https://{hostname}");
        eprintln!("dd-register: auth token signing enabled");
        (Some(b64), Some(issuer))
    };

    let state = AppState {
        hostname: hostname.clone(),
        registry,
        cf,
        auth_public_key_b64,
        auth_issuer,
    };

    // Axum router: 3 endpoints
    let app = Router::new()
        .route("/register", get(ws_register))
        .route("/deregister", post(post_deregister))
        .route("/health", get(get_health))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    eprintln!("dd-register: listening on {addr}");
    eprintln!("dd-register: agents register at wss://{hostname}/register");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            eprintln!("dd-register: shutting down");
        })
        .await
        .expect("server error");
}

// ── Route: /register (WebSocket) ────────────────────────────────────────

async fn ws_register(State(state): State<AppState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    let registry = state.registry.clone();
    let cf = state.cf.clone();
    let auth_key = state.auth_public_key_b64.clone();
    let auth_issuer = state.auth_issuer.clone();
    ws.on_upgrade(move |socket| {
        handler::handle_ws_register(socket, registry, cf, auth_key, auth_issuer)
    })
}

// ── Route: /deregister (POST) ───────────────────────────────────────────

#[derive(serde::Deserialize)]
struct DeregisterRequest {
    agent_id: String,
}

async fn post_deregister(
    State(state): State<AppState>,
    Json(req): Json<DeregisterRequest>,
) -> impl IntoResponse {
    match handler::handle_deregister(state.registry.clone(), &state.cf, &req.agent_id).await {
        Ok(()) => (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({"ok": true})),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

// ── Route: /health (GET) ────────────────────────────────────────────────

async fn get_health(State(state): State<AppState>) -> impl IntoResponse {
    let agents = state.registry.lock().await;
    let agent_list: Vec<serde_json::Value> = agents
        .values()
        .map(|a| {
            serde_json::json!({
                "agent_id": a.agent_id,
                "hostname": a.hostname,
                "vm_name": a.vm_name,
                "status": a.status,
            })
        })
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "hostname": state.hostname,
        "agent_count": agents.len(),
        "agents": agent_list,
    }))
}
