//! dd-register -- minimal tunnel provisioning service.
//!
//! Handles agent registration (Noise XX over WebSocket), CF tunnel lifecycle,
//! and fleet health. No dashboard, no OAuth, no scraping -- those are dd-web's job.

pub mod handler;

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
    /// Our own tunnel ID (used by STONITH to avoid killing ourselves).
    self_tunnel_id: String,
    /// Base64-encoded HMAC secret for agent JWT verification.
    auth_public_key_b64: Option<String>,
    /// Auth issuer URL (https://<hostname>).
    auth_issuer: Option<String>,
}

// ── Entry point ─────────────────────────────────────────────────────────

pub async fn run() {
    // DD_REGISTER_PORT takes precedence (used by unified `dd management`
    // binary where dd-web owns DD_PORT=8080).
    let port: u16 = std::env::var("DD_REGISTER_PORT")
        .or_else(|_| std::env::var("DD_PORT"))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8081);

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

    // Start cloudflared with the tunnel token.
    // If cloudflared exits (e.g. tunnel deleted by a new register's STONITH),
    // power off the VM — fast kill path when cloudflared cooperates.
    let token = tunnel_info.tunnel_token.clone();
    tokio::spawn(async move {
        eprintln!("dd-register: starting cloudflared");
        let mut child = tokio::process::Command::new("cloudflared")
            .args([
                "tunnel",
                "--no-autoupdate",
                "--metrics=",
                "run",
                "--token",
                &token,
            ])
            .spawn()
            .expect("failed to spawn cloudflared");
        let status = child.wait().await;
        eprintln!("dd-register: cloudflared exited: {status:?}");
        eprintln!("dd-register: tunnel lost — powering off (STONITH kill)");
        kernel_poweroff();
    });

    // Self-STONITH watchdog. cloudflared is known to retry indefinitely
    // when its tunnel is deleted remotely instead of exiting, which
    // breaks the cloudflared-child-exit → poweroff path above. Poll
    // CF API every 30s; when we confirm our own tunnel is gone,
    // poweroff directly — no dependency on cloudflared's behaviour.
    let wd_cf = cf.clone();
    let wd_tunnel_id = tunnel_info.tunnel_id.clone();
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        // Give the freshly-created tunnel a moment to propagate in CF's
        // eventual-consistency layer before the first check.
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        // 10s poll. CF API call is sub-second; cost is negligible.
        // Worst-case detection after a STONITH delete: 10s (next poll
        // tick) + reboot syscall + GCP state transition. Keeps the
        // verify-step window in release.yml tight.
        loop {
            if !tunnel::tunnel_exists(&http, &wd_cf, &wd_tunnel_id).await {
                eprintln!("dd-register: own tunnel {wd_tunnel_id} gone — self-STONITH poweroff");
                kernel_poweroff();
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
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
        self_tunnel_id: tunnel_info.tunnel_id.clone(),
        auth_public_key_b64,
        auth_issuer,
    };

    // STONITH: signal old register instances to shut down.
    // After we've self-registered (our tunnel is live), find any OTHER
    // tunnel serving the same hostname and tell it to power off.
    let stonith_state = state.clone();
    tokio::spawn(async move {
        // Give cloudflared a moment to connect before we STONITH.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        stonith_old_registers(&stonith_state).await;
    });

    let app = Router::new()
        .route("/register", get(ws_register))
        .route("/deregister", post(post_deregister))
        .route("/health", get(get_health))
        .route("/stonith", post(post_stonith))
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
    let registered_count = agents.values().filter(|a| a.status == "healthy").count();
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
        "registered_count": registered_count,
        "agents": agent_list,
    }))
}

// ── Route: /stonith (POST) ─────────────────────────────────────────────
// Accepts a shutdown signal from a new register instance. Validates the
// CF API token as a shared secret, then powers off the VM.

async fn post_stonith(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Validate: Authorization header must contain our CF API token.
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let expected = format!("Bearer {}", state.cf.api_token);
    if auth != expected {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok": false, "error": "unauthorized"})),
        );
    }

    eprintln!("dd-register: STONITH received — powering off");

    // Run kernel poweroff after responding so the requester sees an OK.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        eprintln!("dd-register: executing poweroff");
        kernel_poweroff();
    });

    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({"ok": true, "message": "shutting down"})),
    )
}

// ── Kernel poweroff via reboot(2) syscall ───────────────────────────────
// The `poweroff` subprocess proved unreliable on the sealed image:
// busybox poweroff tries to signal a systemd-style PID 1 first and
// silently no-ops when easyenclave (not systemd) doesn't respond.
// Calling reboot(2) directly bypasses all of that — kernel halts the
// VM regardless of who PID 1 is. Requires CAP_SYS_BOOT (we're root).
fn kernel_poweroff() {
    // Best-effort sync before halt so any pending writes to the tmpfs
    // log dir flush to the serial console.
    unsafe {
        libc::sync();
        let rc = libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        // reboot(2) doesn't return on success. If we get here, it failed.
        eprintln!(
            "dd-register: reboot(POWER_OFF) returned {rc}, errno {}",
            *libc::__errno_location()
        );
    }
}

// ── STONITH: delete old register tunnels to trigger poweroff ────────────
// When we delete an old register's CF tunnel, the new VM's STONITH path
// removes the tunnel; the old VM then notices via either (a) cloudflared
// exiting on tunnel-gone (fast path, often unreliable), or (b) the
// self-watchdog polling CF API and triggering kernel_poweroff() (slow
// path, deterministic upper bound 30s).

async fn stonith_old_registers(state: &AppState) {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let tunnels = match tunnel::list_tunnels(&http, &state.cf).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("dd-register: STONITH: failed to list tunnels: {e}");
            return;
        }
    };

    let our_tunnel_id = &state.self_tunnel_id;

    for t in &tunnels {
        let name = t["name"].as_str().unwrap_or_default();
        let id = t["id"].as_str().unwrap_or_default();
        if id.is_empty() || id == our_tunnel_id {
            continue;
        }

        // Previously: reconstruct `{name}.{domain}` and compare to
        // state.hostname. That breaks for CP tunnels, whose hostname
        // is overridden to `app-{env}.{domain}` and doesn't match the
        // tunnel name. Ask CF what this tunnel actually serves.
        let serves_our_host = match tunnel::tunnel_ingress_hostnames(&http, &state.cf, id).await {
            Ok(hosts) => hosts.iter().any(|h| h == &state.hostname),
            Err(e) => {
                eprintln!("dd-register: STONITH: config fetch failed for {name}: {e}");
                false
            }
        };
        if !serves_our_host {
            continue;
        }

        eprintln!("dd-register: STONITH: deleting old tunnel {name} ({id})");
        if let Err(e) = tunnel::delete_tunnel_by_name(&http, &state.cf, name).await {
            eprintln!("dd-register: STONITH: delete failed for {name}: {e}");
        } else {
            eprintln!("dd-register: STONITH: killed old tunnel {name}");
        }
    }

    // DNS record now points at our new tunnel (create_agent_tunnel
    // overwrote it). The old-tunnel DNS cleanup the previous code did
    // here was a no-op because the record name matched ours; leaving
    // it out so we don't risk deleting our own record.
}
