//! DD Register — fleet entry point.
//!
//! Runs on the bootstrap VM. Self-registers a CF tunnel, serves the fleet
//! dashboard, and handles agent registrations. Agents connect via Noise
//! WebSocket to get their own tunnel tokens.

use axum::extract::ws::{Message, WebSocket};
use axum::extract::WebSocketUpgrade;
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use dd_agent::noise::{self, AttestationPayload, BootstrapConfig};
use dd_agent::tunnel::{self, CfConfig};

#[derive(Debug, Clone, serde::Serialize)]
struct AgentRecord {
    agent_id: String,
    hostname: String,
    vm_name: String,
    attestation_type: String,
    registered_at: String,
}

type AgentRegistry = Arc<Mutex<HashMap<String, AgentRecord>>>;

#[derive(Debug, serde::Deserialize)]
struct RegisterRequest {
    owner: String,
    vm_name: String,
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("DD_REGISTER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let cf = match CfConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dd-register: {e}");
            eprintln!("dd-register: set DD_CF_API_TOKEN, DD_CF_ACCOUNT_ID, DD_CF_ZONE_ID");
            std::process::exit(1);
        }
    };

    // Self-register: create our own CF tunnel
    let hostname = std::env::var("DD_HOSTNAME").unwrap_or_else(|_| {
        eprintln!("dd-register: DD_HOSTNAME not set");
        std::process::exit(1);
    });

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

    eprintln!("dd-register: tunnel created — {}", tunnel_info.hostname);

    // Spawn cloudflared
    let token = tunnel_info.tunnel_token.clone();
    tokio::spawn(async move {
        eprintln!("dd-register: starting cloudflared");
        let mut child = tokio::process::Command::new("cloudflared")
            .args(["tunnel", "--no-autoupdate", "run", "--token", &token])
            .spawn()
            .expect("failed to spawn cloudflared");
        let _ = child.wait().await;
        eprintln!("dd-register: cloudflared exited");
    });

    let registry: AgentRegistry = Arc::new(Mutex::new(HashMap::new()));
    let env_label = std::env::var("DD_ENV").unwrap_or_else(|_| "dev".into());

    let dashboard_registry = registry.clone();
    let dashboard_cf = cf.clone();
    let dashboard_env = env_label.clone();
    let dashboard_hostname = hostname.clone();

    let register_cf = cf.clone();
    let register_registry = registry.clone();

    let app = Router::new()
        .route(
            "/",
            get(move || {
                let reg = dashboard_registry.clone();
                let cf = dashboard_cf.clone();
                let env = dashboard_env.clone();
                let host = dashboard_hostname.clone();
                async move { fleet_dashboard(reg, cf, env, host).await }
            }),
        )
        .route(
            "/health",
            get(|| async { axum::Json(serde_json::json!({"ok": true, "service": "dd-register"})) }),
        )
        .route(
            "/register",
            get(move |ws: WebSocketUpgrade| {
                let cf = register_cf.clone();
                let reg = register_registry.clone();
                async move { ws.on_upgrade(move |socket| handle_registration(socket, cf, reg)) }
            }),
        );

    let addr = format!("0.0.0.0:{port}");
    eprintln!("dd-register: listening on {addr}");
    eprintln!("dd-register: dashboard at https://{hostname}/");
    eprintln!("dd-register: agents register at wss://{hostname}/register");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}

// ── Fleet Dashboard ──────────────────────────────────────────────────────

async fn fleet_dashboard(
    registry: AgentRegistry,
    _cf: CfConfig,
    env: String,
    hostname: String,
) -> Html<String> {
    let agents = registry.lock().await;

    let mut rows = String::new();
    for agent in agents.values() {
        rows.push_str(&format!(
            r#"<tr>
                <td><a href="https://{hostname}">{hostname}</a></td>
                <td>{vm_name}</td>
                <td><span style="color:#a6e3a1">registered</span></td>
                <td>{att}</td>
                <td>{registered}</td>
            </tr>"#,
            hostname = agent.hostname,
            vm_name = agent.vm_name,
            att = agent.attestation_type,
            registered = agent
                .registered_at
                .split('T')
                .next()
                .unwrap_or(&agent.registered_at),
        ));
    }

    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>DD Fleet — {env}</title>
<style>
  body {{ margin: 0; background: #1e1e2e; color: #cdd6f4; font-family: 'JetBrains Mono', monospace; padding: 24px; }}
  h1 {{ color: #89b4fa; margin: 0 0 4px; font-size: 20px; }}
  .subtitle {{ color: #585b70; font-size: 12px; margin-bottom: 16px; }}
  .meta {{ color: #a6adc8; font-size: 13px; margin-bottom: 24px; }}
  .meta .ok {{ color: #a6e3a1; }}
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
<div class="subtitle">{env} fleet</div>
<div class="meta">
  <span class="ok">healthy</span> &middot; {hostname} &middot; {count} agent(s) registered
</div>

<div class="section">Agents ({count})</div>
{table}
</body>
</html>"#,
        env = env,
        hostname = hostname,
        count = agents.len(),
        table = if agents.is_empty() {
            r#"<div class="empty">no agents registered &mdash; start a dd-agent with DD_REGISTER_URL pointing here</div>"#.to_string()
        } else {
            format!(
                r#"<table>
<tr><th>hostname</th><th>vm</th><th>status</th><th>attestation</th><th>registered</th></tr>
{rows}
</table>"#
            )
        },
    ))
}

// ── Agent Registration ───────────────────────────────────────────────────

async fn handle_registration(socket: WebSocket, cf: CfConfig, registry: AgentRegistry) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    let keypair = match noise::generate_keypair() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("dd-register: keypair: {e}");
            return;
        }
    };

    let mut noise = match snow::Builder::new(noise::NOISE_PATTERN.parse().unwrap())
        .local_private_key(&keypair.private)
        .and_then(|b| b.build_responder())
    {
        Ok(n) => n,
        Err(e) => {
            eprintln!("dd-register: noise setup: {e}");
            return;
        }
    };

    let mut buf = vec![0u8; 65535];

    // XX handshake
    let msg1 = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        _ => return,
    };
    if noise.read_message(&msg1, &mut buf).is_err() {
        return;
    }

    let mut msg2_buf = vec![0u8; 65535];
    let msg2_len = match noise.write_message(&[], &mut msg2_buf) {
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

    let attestation: AttestationPayload = match serde_json::from_slice(&buf[..payload_len]) {
        Ok(a) => a,
        Err(_) => return,
    };

    eprintln!(
        "dd-register: agent {} ({})",
        attestation.vm_name, attestation.attestation_type
    );

    let mut transport = match noise.into_transport_mode() {
        Ok(t) => t,
        Err(_) => return,
    };

    // Read registration request
    let enc_req = match ws_rx.next().await {
        Some(Ok(Message::Binary(data))) => data.to_vec(),
        _ => return,
    };
    let req_len = match transport.read_message(&enc_req, &mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let reg: RegisterRequest = match serde_json::from_slice(&buf[..req_len]) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Create tunnel for the agent
    let client = reqwest::Client::new();
    let agent_id = uuid::Uuid::new_v4().to_string();
    let tunnel_info =
        match tunnel::create_agent_tunnel(&client, &cf, &agent_id, &reg.vm_name, None).await {
            Ok(info) => info,
            Err(e) => {
                eprintln!("dd-register: tunnel failed: {e}");
                return;
            }
        };

    eprintln!(
        "dd-register: {} registered at {}",
        reg.vm_name, tunnel_info.hostname
    );

    // Record in registry
    registry.lock().await.insert(
        agent_id.clone(),
        AgentRecord {
            agent_id,
            hostname: tunnel_info.hostname.clone(),
            vm_name: reg.vm_name.clone(),
            attestation_type: attestation.attestation_type,
            registered_at: chrono::Utc::now().to_rfc3339(),
        },
    );

    // Send bootstrap config
    let config = BootstrapConfig {
        owner: reg.owner,
        tunnel_token: tunnel_info.tunnel_token,
        hostname: tunnel_info.hostname,
        auth_public_key: None,
        auth_issuer: None,
    };
    let config_json = serde_json::to_vec(&config).unwrap();
    let mut enc_resp = vec![0u8; 65535];
    if let Ok(len) = transport.write_message(&config_json, &mut enc_resp) {
        let _ = ws_tx
            .send(Message::Binary(enc_resp[..len].to_vec().into()))
            .await;
    }
}
