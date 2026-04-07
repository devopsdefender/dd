//! DD Register — fleet entry point.
//!
//! Runs on the bootstrap VM. Self-registers a CF tunnel, serves the fleet
//! dashboard, and handles agent registrations. Agents connect via Noise
//! WebSocket to get their own tunnel tokens.

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use dd_agent::noise::{
    self, AttestationPayload, BootstrapConfig, LeaseRenewRequest, LeaseRenewResponse,
    RegisterRequest,
};
use dd_agent::tunnel::{self, CfConfig};

#[derive(Debug, Clone, serde::Serialize)]
struct AgentRecord {
    agent_id: String,
    hostname: String,
    vm_name: String,
    attestation_type: String,
    registered_at: String,
    last_seen: String,
    status: String,
    deployment_count: usize,
    deployment_names: Vec<String>,
    cpu_percent: u64,
    memory_used_mb: u64,
    memory_total_mb: u64,
}

type AgentRegistry = Arc<Mutex<HashMap<String, AgentRecord>>>;

#[derive(Debug, serde::Deserialize)]
struct DeregisterRequest {
    agent_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct AgentHealthReport {
    hostname: String,
    healthy: bool,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    vm_name: Option<String>,
    #[serde(default)]
    attestation_type: Option<String>,
    #[serde(default)]
    deployment_count: Option<usize>,
    #[serde(default)]
    deployments: Option<Vec<String>>,
    #[serde(default)]
    cpu_percent: Option<u64>,
    #[serde(default)]
    memory_used_mb: Option<u64>,
    #[serde(default)]
    memory_total_mb: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct FleetReport {
    agents: Vec<AgentHealthReport>,
    #[serde(default)]
    orphan_tunnels: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
struct FleetReportAck {
    ok: bool,
    healthy_agents: usize,
    stale_agents: usize,
    orphan_tunnels: usize,
    dead_agents_cleaned: usize,
}

#[derive(Debug, serde::Serialize)]
struct FleetSnapshot {
    env: String,
    total_agents: usize,
    healthy_agents: usize,
    stale_agents: usize,
    dead_agents: usize,
    agents: Vec<AgentRecord>,
}

fn register_lease_ttl_secs() -> u64 {
    std::env::var("DD_REGISTER_LEASE_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(90)
}

fn register_epoch() -> u64 {
    std::env::var("DD_REGISTER_EPOCH")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1)
}

fn register_redirect_url() -> Option<String> {
    std::env::var("DD_REGISTER_REDIRECT_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("DD_REGISTER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let bind_addr = std::env::var("DD_REGISTER_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".into());

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
        let mut cmd = tokio::process::Command::new("cloudflared");
        cmd.args(["tunnel", "--no-autoupdate", "run", "--token", &token]);
        configure_parent_death_signal(&mut cmd);
        let mut child = cmd.spawn().expect("failed to spawn cloudflared");
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
    let deregister_cf = cf.clone();
    let deregister_registry = registry.clone();
    let report_registry = registry.clone();
    let fleet_registry = registry.clone();

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
        )
        .route(
            "/deregister",
            post(move |Json(req): Json<DeregisterRequest>| {
                let cf = deregister_cf.clone();
                let reg = deregister_registry.clone();
                async move { post_deregister(cf, reg, req).await }
            }),
        )
        .route(
            "/api/fleet/report",
            post(
                move |ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
                      headers: HeaderMap,
                      Json(report): Json<FleetReport>| {
                    let cf = cf.clone();
                    let reg = report_registry.clone();
                    async move { post_fleet_report(addr, headers, cf, reg, report).await }
                },
            ),
        );
    let app = app.route(
        "/api/fleet",
        get({
            let registry = fleet_registry.clone();
            let env_label = env_label.clone();
            move |ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>, headers: HeaderMap| {
                let registry = registry.clone();
                let env_label = env_label.clone();
                async move {
                    if !is_authorized_admin_api_request(&headers, addr.ip().is_loopback()) {
                        return (
                            axum::http::StatusCode::UNAUTHORIZED,
                            Json(serde_json::json!({"error": "authentication required"})),
                        )
                            .into_response();
                    }
                    Json(fleet_snapshot(&registry, &env_label).await).into_response()
                }
            }
        }),
    );

    let addr = format!("{bind_addr}:{port}");
    eprintln!("dd-register: listening on {addr}");
    eprintln!("dd-register: dashboard at https://{hostname}/");
    eprintln!("dd-register: agents register at wss://{hostname}/register");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
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
                <td>{status}</td>
                <td>{att}</td>
                <td>{registered}</td>
            </tr>"#,
            hostname = agent.hostname,
            vm_name = agent.vm_name,
            status = agent.status,
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
    let attestation_backend = dd_agent::attestation::detect();
    let register_vm_name = std::env::var("DD_HOSTNAME").unwrap_or_else(|_| "dd-register".into());

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

    let attestation = noise::build_attestation_payload(
        &register_vm_name,
        None,
        attestation_backend.as_ref(),
        &keypair.public,
    );
    let attestation_json = serde_json::to_vec(&attestation).unwrap();
    let mut msg2_buf = vec![0u8; 65535];
    let msg2_len = match noise.write_message(&attestation_json, &mut msg2_buf) {
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
    let remote_static = match noise.get_remote_static() {
        Some(key) => key,
        None => return,
    };
    if let Err(error) = noise::verify_remote_attestation(&attestation, remote_static) {
        eprintln!("dd-register: attestation verify failed: {error}");
        return;
    }

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
    let tunnel_info =
        match tunnel::create_agent_tunnel(&client, &cf, &reg.agent_id, &reg.vm_name, None).await {
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
        reg.agent_id.clone(),
        AgentRecord {
            agent_id: reg.agent_id.clone(),
            hostname: tunnel_info.hostname.clone(),
            vm_name: reg.vm_name.clone(),
            attestation_type: attestation.attestation_type,
            registered_at: chrono::Utc::now().to_rfc3339(),
            last_seen: chrono::Utc::now().to_rfc3339(),
            status: "healthy".into(),
            deployment_count: 0,
            deployment_names: Vec::new(),
            cpu_percent: 0,
            memory_used_mb: 0,
            memory_total_mb: 0,
        },
    );

    // Send bootstrap config
    let config = BootstrapConfig {
        agent_id: reg.agent_id,
        owner: reg.owner,
        tunnel_token: tunnel_info.tunnel_token,
        hostname: tunnel_info.hostname,
        lease_ttl_secs: register_lease_ttl_secs(),
        register_epoch: register_epoch(),
        redirect_url: register_redirect_url(),
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

    while let Some(Ok(Message::Binary(data))) = ws_rx.next().await {
        let renew_len = match transport.read_message(&data, &mut buf) {
            Ok(n) => n,
            Err(_) => break,
        };
        let renew: LeaseRenewRequest = match serde_json::from_slice(&buf[..renew_len]) {
            Ok(r) => r,
            Err(_) => break,
        };
        let current_epoch = register_epoch();
        let current_ttl = register_lease_ttl_secs();
        let redirect_url = register_redirect_url();
        let revoked = {
            let mut registry = registry.lock().await;
            match registry.get_mut(&renew.agent_id) {
                Some(agent) if renew.agent_id == config.agent_id && agent.status != "dead" => {
                    agent.last_seen = chrono::Utc::now().to_rfc3339();
                    agent.status = "healthy".into();
                    false
                }
                _ => true,
            }
        };
        let response = LeaseRenewResponse {
            ok: !revoked,
            lease_ttl_secs: current_ttl,
            register_epoch: current_epoch,
            revoked,
            redirect_url,
        };
        let json = serde_json::to_vec(&response).unwrap();
        let mut enc_resp = vec![0u8; 65535];
        let len = match transport.write_message(&json, &mut enc_resp) {
            Ok(n) => n,
            Err(_) => break,
        };
        if ws_tx
            .send(Message::Binary(enc_resp[..len].to_vec().into()))
            .await
            .is_err()
        {
            break;
        }
        if revoked {
            eprintln!("dd-register: revoked agent {}", renew.agent_id);
            break;
        }
    }
}

async fn post_deregister(
    cf: CfConfig,
    registry: AgentRegistry,
    req: DeregisterRequest,
) -> Json<serde_json::Value> {
    let agent = registry.lock().await.remove(&req.agent_id);
    if let Some(agent) = agent {
        let client = reqwest::Client::new();
        if let Err(e) = tunnel::remove_agent(&client, &cf, &agent.agent_id, &agent.hostname).await {
            eprintln!("dd-register: deregister tunnel cleanup failed: {e}");
        } else {
            eprintln!(
                "dd-register: deregistered {} ({})",
                agent.agent_id, agent.hostname
            );
        }
        Json(serde_json::json!({"ok": true}))
    } else {
        Json(serde_json::json!({"ok": true, "removed": false}))
    }
}

async fn post_fleet_report(
    addr: std::net::SocketAddr,
    headers: HeaderMap,
    cf: CfConfig,
    registry: AgentRegistry,
    report: FleetReport,
) -> impl axum::response::IntoResponse {
    if !is_authorized_scraper_report_request(&headers, addr.ip().is_loopback()) {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "authentication required"})),
        )
            .into_response();
    }

    Json(apply_fleet_report(&cf, &registry, report).await).into_response()
}

async fn apply_fleet_report(
    cf: &CfConfig,
    registry: &AgentRegistry,
    report: FleetReport,
) -> FleetReportAck {
    let mut registry_guard = registry.lock().await;
    let mut healthy_count = 0usize;
    let mut stale_count = 0usize;

    for agent_report in &report.agents {
        if agent_report.healthy {
            healthy_count += 1;
            if let Some(existing) = registry_guard
                .values_mut()
                .find(|a| a.hostname == agent_report.hostname)
            {
                existing.status = "healthy".into();
                existing.last_seen = chrono::Utc::now().to_rfc3339();
                if let Some(deployment_count) = agent_report.deployment_count {
                    existing.deployment_count = deployment_count;
                }
                if let Some(ref deployments) = agent_report.deployments {
                    existing.deployment_names = deployments.clone();
                }
                if let Some(cpu_percent) = agent_report.cpu_percent {
                    existing.cpu_percent = cpu_percent;
                }
                if let Some(memory_used_mb) = agent_report.memory_used_mb {
                    existing.memory_used_mb = memory_used_mb;
                }
                if let Some(memory_total_mb) = agent_report.memory_total_mb {
                    existing.memory_total_mb = memory_total_mb;
                }
            } else if let Some(ref aid) = agent_report.agent_id {
                registry_guard.insert(
                    aid.clone(),
                    AgentRecord {
                        agent_id: aid.clone(),
                        hostname: agent_report.hostname.clone(),
                        vm_name: agent_report.vm_name.clone().unwrap_or_default(),
                        attestation_type: agent_report
                            .attestation_type
                            .clone()
                            .unwrap_or_else(|| "unknown".into()),
                        registered_at: chrono::Utc::now().to_rfc3339(),
                        last_seen: chrono::Utc::now().to_rfc3339(),
                        status: "healthy".into(),
                        deployment_count: agent_report.deployment_count.unwrap_or(0),
                        deployment_names: agent_report.deployments.clone().unwrap_or_default(),
                        cpu_percent: agent_report.cpu_percent.unwrap_or(0),
                        memory_used_mb: agent_report.memory_used_mb.unwrap_or(0),
                        memory_total_mb: agent_report.memory_total_mb.unwrap_or(0),
                    },
                );
                eprintln!(
                    "dd-register: scraper discovered new agent {aid} at {}",
                    agent_report.hostname
                );
            }
        } else {
            stale_count += 1;
            if let Some(existing) = registry_guard
                .values_mut()
                .find(|a| a.hostname == agent_report.hostname)
            {
                if existing.status == "healthy" {
                    existing.status = "stale".into();
                    eprintln!(
                        "dd-register: scraper: {} stale ({})",
                        existing.hostname,
                        agent_report.error.as_deref().unwrap_or("unreachable")
                    );
                } else if existing.status == "stale" {
                    existing.status = "dead".into();
                    eprintln!("dd-register: scraper: {} dead", existing.hostname);
                }
            }
        }
    }

    let dead: Vec<(String, String)> = registry_guard
        .values()
        .filter(|a| a.status == "dead")
        .map(|a| (a.agent_id.clone(), a.hostname.clone()))
        .collect();
    drop(registry_guard);

    for (agent_id, hostname) in &dead {
        let client = reqwest::Client::new();
        if let Err(e) = tunnel::remove_agent(&client, cf, agent_id, hostname).await {
            eprintln!("dd-register: scraper cleanup failed for {hostname}: {e}");
        } else {
            eprintln!("dd-register: scraper cleaned up {hostname}");
        }
        registry.lock().await.remove(agent_id);
    }

    for tunnel_name in &report.orphan_tunnels {
        let client = reqwest::Client::new();
        if let Err(e) = tunnel::delete_tunnel_by_name(&client, cf, tunnel_name).await {
            eprintln!("dd-register: scraper orphan cleanup failed for {tunnel_name}: {e}");
        } else {
            eprintln!("dd-register: scraper cleaned orphan tunnel {tunnel_name}");
        }
    }

    eprintln!(
        "dd-register: scraper report: {} healthy, {} stale/unreachable, {} orphan tunnels, {} dead cleaned",
        healthy_count,
        stale_count,
        report.orphan_tunnels.len(),
        dead.len()
    );

    FleetReportAck {
        ok: true,
        healthy_agents: healthy_count,
        stale_agents: stale_count,
        orphan_tunnels: report.orphan_tunnels.len(),
        dead_agents_cleaned: dead.len(),
    }
}

async fn fleet_snapshot(registry: &AgentRegistry, env: &str) -> FleetSnapshot {
    let mut agents: Vec<AgentRecord> = registry.lock().await.values().cloned().collect();
    agents.sort_by(|left, right| left.hostname.cmp(&right.hostname));
    let total_agents = agents.len();
    let healthy_agents = agents
        .iter()
        .filter(|agent| agent.status == "healthy")
        .count();
    let stale_agents = agents
        .iter()
        .filter(|agent| agent.status == "stale")
        .count();
    let dead_agents = agents.iter().filter(|agent| agent.status == "dead").count();

    FleetSnapshot {
        env: env.to_string(),
        total_agents,
        healthy_agents,
        stale_agents,
        dead_agents,
        agents,
    }
}

fn configure_parent_death_signal(cmd: &mut tokio::process::Command) {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

fn is_authorized_admin_api_request(headers: &HeaderMap, is_loopback: bool) -> bool {
    if is_loopback {
        return true;
    }

    match std::env::var("DD_ADMIN_API_TOKEN") {
        Ok(expected) if !expected.is_empty() => extract_bearer_token(headers)
            .map(|token| token == expected)
            .unwrap_or(false),
        _ => false,
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or(value.strip_prefix("bearer "))?;
    Some(token.to_string())
}

fn is_authorized_scraper_report_request(headers: &HeaderMap, is_loopback: bool) -> bool {
    if is_loopback {
        return true;
    }

    match std::env::var("DD_SCRAPER_REPORT_TOKEN") {
        Ok(expected) if !expected.is_empty() => extract_bearer_token(headers)
            .map(|token| token == expected)
            .unwrap_or(false),
        _ => false,
    }
}
