use axum::extract::ws::{Message, WebSocket};
use axum::extract::{OriginalUri, Path, State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};

use crate::common::error::AppError;

use super::{format_uptime, nav_bar, page_shell, require_browser_token};
use super::{AgentState, RegisteredAgent};

#[derive(Debug, Deserialize)]
struct DashQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct DeregisterRequest {
    agent_id: String,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
struct FleetReport {
    agents: Vec<AgentHealthReport>,
    #[serde(default)]
    orphan_tunnels: Vec<String>,
}

#[derive(Serialize)]
struct FleetReportAck {
    ok: bool,
    healthy_agents: usize,
    stale_agents: usize,
    orphan_tunnels: usize,
    dead_agents_cleaned: usize,
}

pub(super) fn add_routes(router: Router<AgentState>) -> Router<AgentState> {
    router
        .route("/", get(fleet_dashboard))
        .route("/agent/{agent_id}", get(agent_detail))
        .route("/register", get(ws_register))
        .route("/scraper", get(ws_scraper))
        .route("/api/fleet/report", post(post_fleet_report))
        .route("/deregister", post(post_deregister))
}

async fn fleet_dashboard(
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

    Ok(fleet_dashboard_html(&state).await.into_response())
}

async fn fleet_dashboard_html(state: &AgentState) -> Html<String> {
    let agents = state.agent_registry.lock().await;
    let env = std::env::var("DD_ENV").unwrap_or_else(|_| "dev".into());
    let now = chrono::Utc::now();

    let mut rows = String::new();
    for a in agents.values() {
        let age_secs = now.signed_duration_since(a.last_seen).num_seconds();
        let last_seen = if age_secs < 60 {
            format!("{age_secs}s ago")
        } else if age_secs < 3600 {
            format!("{}m ago", age_secs / 60)
        } else {
            format!("{}h ago", age_secs / 3600)
        };
        let mem_str = if a.memory_total_mb > 0 {
            format!("{}M / {}M", a.memory_used_mb, a.memory_total_mb)
        } else {
            "-".into()
        };
        rows.push_str(&format!(
            r#"<tr>
                <td><a href="/agent/{agent_id}">{hostname}</a></td>
                <td>{vm}</td>
                <td><span class="pill {status}">{status}</span></td>
                <td>{attestation}</td>
                <td>{deploys}</td>
                <td>{cpu}%</td>
                <td>{mem}</td>
                <td>{last_seen}</td>
            </tr>"#,
            agent_id = a.agent_id,
            hostname = a.hostname,
            vm = a.vm_name,
            status = a.status,
            attestation = a.attestation_type,
            deploys = if a.deployment_names.is_empty() {
                format!("{}", a.deployment_count)
            } else {
                a.deployment_names.join(", ")
            },
            cpu = a.cpu_percent,
            mem = mem_str,
            last_seen = last_seen,
        ));
    }

    let uptime_str = format_uptime(state.started_at.elapsed().as_secs());
    let nav = nav_bar(&[("Fleet", "/", true)]);

    let agents_count = agents.len();
    let agent_table = if agents.is_empty() {
        r#"<div class="empty">No agents registered</div>"#.to_string()
    } else {
        format!(
            r#"<table><tr><th>hostname</th><th>vm</th><th>status</th><th>attestation</th><th>workloads</th><th>cpu</th><th>memory</th><th>last seen</th></tr>{rows}</table>"#
        )
    };

    drop(agents);
    let deps = state.deployments.lock().await;
    let workload_rows = if deps.is_empty() {
        r#"<div class="empty">No workloads running</div>"#.to_string()
    } else {
        let mut wr = String::new();
        for d in deps.values() {
            let status_class = match d.status.as_str() {
                "running" => "running",
                "deploying" => "deploying",
                "failed" | "exited" => "failed",
                _ => "idle",
            };
            let session_link = if d.status == "running" {
                format!(
                    r#"<a href="/session/{name}">session</a>"#,
                    name = d.app_name
                )
            } else {
                r#"<span class="dim">—</span>"#.to_string()
            };
            wr.push_str(&format!(
                r#"<tr><td><a href="/workload/{id}">{name}</a></td><td><span class="pill {status_class}">{status}</span></td><td class="dim">{image}</td><td>{session_link}</td></tr>"#,
                id = d.id,
                name = d.app_name,
                status = d.status,
                image = d.image,
            ));
        }
        format!(
            r#"<table><tr><th>app</th><th>status</th><th>image</th><th>session</th></tr>{wr}</table>"#
        )
    };

    let content = format!(
        r#"<h1>DevOps Defender</h1>
<div class="sub">{env} fleet &middot; {agent_id}</div>
<div class="meta"><span class="ok">healthy</span> &middot; uptime {uptime} &middot; {count} agent(s)</div>
<div class="section">Agents</div>
{agent_table}
<div class="section">Workloads</div>
{workload_rows}"#,
        env = env,
        agent_id = &state.agent_id[..8],
        uptime = uptime_str,
        count = agents_count,
        agent_table = agent_table,
        workload_rows = workload_rows,
    );

    Html(page_shell(&format!("DD Fleet — {env}"), &nav, &content))
}

async fn agent_detail(Path(agent_id): Path<String>, State(state): State<AgentState>) -> Response {
    let agents = state.agent_registry.lock().await;
    let Some(a) = agents.get(&agent_id) else {
        return (axum::http::StatusCode::NOT_FOUND, "agent not found").into_response();
    };

    let now = chrono::Utc::now();
    let age_secs = now.signed_duration_since(a.last_seen).num_seconds();
    let last_seen = if age_secs < 60 {
        format!("{age_secs}s ago")
    } else if age_secs < 3600 {
        format!("{}m ago", age_secs / 60)
    } else {
        format!("{}h ago", age_secs / 3600)
    };

    let mem_str = if a.memory_total_mb > 0 {
        format!("{}M / {}M", a.memory_used_mb, a.memory_total_mb)
    } else {
        "-".into()
    };

    let workloads = if a.deployment_names.is_empty() {
        format!(
            r#"<span class="dim">{} deployment(s)</span>"#,
            a.deployment_count
        )
    } else {
        a.deployment_names
            .iter()
            .map(|d| {
                format!(
                    r#"<li><a href="https://{hostname}/session/{d}" target="_blank">{d}</a></li>"#,
                    hostname = a.hostname,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let nav = nav_bar(&[("Fleet", "/", false)]);
    let content = format!(
        r#"<div class="back"><a href="/">&larr; fleet</a></div>
<h1>{hostname}</h1>
<div class="sub">{agent_id}</div>

<div class="card">
  <div class="row"><span class="label">Status</span><span class="pill {status}">{status}</span></div>
  <div class="row"><span class="label">VM</span><span>{vm}</span></div>
  <div class="row"><span class="label">Attestation</span><span>{attestation}</span></div>
  <div class="row"><span class="label">Registered</span><span>{registered_at}</span></div>
  <div class="row"><span class="label">Last Seen</span><span>{last_seen}</span></div>
  <div class="row"><span class="label">Tunnel</span><span><a href="https://{hostname}" target="_blank">{hostname} &nearr;</a></span></div>
</div>

<div class="cards">
  <div class="card"><div class="label">CPU</div><div class="value green">{cpu}%</div></div>
  <div class="card"><div class="label">Memory</div><div class="value blue">{mem}</div></div>
</div>

<div class="section">Workloads</div>
<div class="card"><ul>{workloads}</ul></div>"#,
        hostname = a.hostname,
        agent_id = a.agent_id,
        status = a.status,
        vm = a.vm_name,
        attestation = a.attestation_type,
        registered_at = a.registered_at,
        last_seen = last_seen,
        cpu = a.cpu_percent,
        mem = mem_str,
        workloads = workloads,
    );

    Html(page_shell(
        &format!("{} — DD Fleet", a.hostname),
        &nav,
        &content,
    ))
    .into_response()
}

async fn post_deregister(
    State(state): State<AgentState>,
    Json(req): Json<DeregisterRequest>,
) -> Response {
    let agent = state.agent_registry.lock().await.remove(&req.agent_id);
    if let Some(agent) = agent {
        if let Some(cf) = &state.cf_config {
            let client = reqwest::Client::new();
            if let Err(e) =
                crate::tunnel::remove_agent(&client, cf, &agent.agent_id, &agent.hostname).await
            {
                eprintln!("dd-register: deregister tunnel cleanup failed: {e}");
            } else {
                eprintln!(
                    "dd-register: deregistered {} ({})",
                    agent.agent_id, agent.hostname
                );
            }
        }
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({"ok": true})),
        )
            .into_response()
    } else {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent not found"})),
        )
            .into_response()
    }
}

async fn ws_scraper(State(state): State<AgentState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_scraper(socket, state))
}

async fn post_fleet_report(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(report): Json<FleetReport>,
) -> Response {
    if !addr.ip().is_loopback() && super::verify_owner(&state, &headers).await.is_err() {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "authentication required"})),
        )
            .into_response();
    }

    let ack = apply_fleet_report(&state, report).await;
    Json(ack).into_response()
}

async fn handle_ws_scraper(socket: WebSocket, state: AgentState) {
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

    let msg1 = match ws_rx.next().await {
        Some(Ok(Message::Binary(d))) => d.to_vec(),
        _ => return,
    };
    if noise.read_message(&msg1, &mut buf).is_err() {
        return;
    }

    let mut msg2 = vec![0u8; 65535];
    let len = match noise.write_message(&[], &mut msg2) {
        Ok(n) => n,
        Err(_) => return,
    };
    if ws_tx
        .send(Message::Binary(msg2[..len].to_vec().into()))
        .await
        .is_err()
    {
        return;
    }

    let msg3 = match ws_rx.next().await {
        Some(Ok(Message::Binary(d))) => d.to_vec(),
        _ => return,
    };
    let payload_len = match noise.read_message(&msg3, &mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };

    let attestation: crate::noise::AttestationPayload =
        match serde_json::from_slice(&buf[..payload_len]) {
            Ok(a) => a,
            Err(_) => return,
        };
    eprintln!(
        "dd-register: scraper connected (attestation: {})",
        attestation.attestation_type
    );

    let mut transport = match noise.into_transport_mode() {
        Ok(t) => t,
        Err(_) => return,
    };

    while let Some(Ok(Message::Binary(data))) = ws_rx.next().await {
        let data = data.to_vec();
        let dec_len = match transport.read_message(&data, &mut buf) {
            Ok(n) => n,
            Err(_) => break,
        };

        let report: FleetReport = match serde_json::from_slice(&buf[..dec_len]) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("dd-register: bad fleet report: {e}");
                continue;
            }
        };

        let ack = apply_fleet_report(&state, report).await;

        let ack = serde_json::to_string(&ack).unwrap_or_else(|_| "{\"ok\":true}".into());
        let mut enc = vec![0u8; 65535];
        if let Ok(len) = transport.write_message(ack.as_bytes(), &mut enc) {
            let _ = ws_tx
                .send(Message::Binary(enc[..len].to_vec().into()))
                .await;
        }
    }

    eprintln!("dd-register: scraper disconnected");
}

async fn apply_fleet_report(state: &AgentState, report: FleetReport) -> FleetReportAck {
    let now = chrono::Utc::now();
    let mut registry = state.agent_registry.lock().await;
    let mut healthy_count = 0usize;
    let mut stale_count = 0usize;

    for agent_report in &report.agents {
        if agent_report.healthy {
            healthy_count += 1;
            if let Some(existing) = registry
                .values_mut()
                .find(|a| a.hostname == agent_report.hostname)
            {
                existing.last_seen = now;
                existing.status = "healthy".into();
                if let Some(dc) = agent_report.deployment_count {
                    existing.deployment_count = dc;
                }
                if let Some(cpu) = agent_report.cpu_percent {
                    existing.cpu_percent = cpu;
                }
                if let Some(mem_used) = agent_report.memory_used_mb {
                    existing.memory_used_mb = mem_used;
                }
                if let Some(mem_total) = agent_report.memory_total_mb {
                    existing.memory_total_mb = mem_total;
                }
                if let Some(ref names) = agent_report.deployments {
                    existing.deployment_names = names.clone();
                }
            } else if let Some(ref aid) = agent_report.agent_id {
                registry.insert(
                    aid.clone(),
                    RegisteredAgent {
                        agent_id: aid.clone(),
                        hostname: agent_report.hostname.clone(),
                        vm_name: agent_report.vm_name.clone().unwrap_or_default(),
                        attestation_type: agent_report
                            .attestation_type
                            .clone()
                            .unwrap_or_else(|| "unknown".into()),
                        registered_at: now.to_rfc3339(),
                        last_seen: now,
                        status: "healthy".into(),
                        deployment_count: agent_report.deployment_count.unwrap_or(0),
                        deployment_names: Vec::new(),
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
            if let Some(existing) = registry
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

    let dead: Vec<(String, String)> = registry
        .values()
        .filter(|a| a.status == "dead")
        .map(|a| (a.agent_id.clone(), a.hostname.clone()))
        .collect();
    drop(registry);

    for (agent_id, hostname) in &dead {
        if let Some(cf) = &state.cf_config {
            let client = reqwest::Client::new();
            if let Err(e) = crate::tunnel::remove_agent(&client, cf, agent_id, hostname).await {
                eprintln!("dd-register: scraper cleanup failed for {hostname}: {e}");
            } else {
                eprintln!("dd-register: scraper cleaned up {hostname}");
            }
        }
        state.agent_registry.lock().await.remove(agent_id);
    }

    for tunnel_name in &report.orphan_tunnels {
        if let Some(cf) = &state.cf_config {
            let client = reqwest::Client::new();
            if let Err(e) = crate::tunnel::delete_tunnel_by_name(&client, cf, tunnel_name).await {
                eprintln!("dd-register: scraper orphan cleanup failed for {tunnel_name}: {e}");
            } else {
                eprintln!("dd-register: scraper cleaned orphan tunnel {tunnel_name}");
            }
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

async fn ws_register(State(state): State<AgentState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_register(socket, state))
}

async fn handle_ws_register(socket: WebSocket, state: AgentState) {
    let cf = match &state.cf_config {
        Some(cf) => cf.clone(),
        None => {
            eprintln!("dd-register: no CF config, can't register agents");
            return;
        }
    };

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

    let msg1 = match ws_rx.next().await {
        Some(Ok(Message::Binary(d))) => d.to_vec(),
        _ => return,
    };
    if noise.read_message(&msg1, &mut buf).is_err() {
        return;
    }

    let mut msg2 = vec![0u8; 65535];
    let len = match noise.write_message(&[], &mut msg2) {
        Ok(n) => n,
        Err(_) => return,
    };
    if ws_tx
        .send(Message::Binary(msg2[..len].to_vec().into()))
        .await
        .is_err()
    {
        return;
    }

    let msg3 = match ws_rx.next().await {
        Some(Ok(Message::Binary(d))) => d.to_vec(),
        _ => return,
    };
    let payload_len = match noise.read_message(&msg3, &mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };

    let attestation: crate::noise::AttestationPayload =
        match serde_json::from_slice(&buf[..payload_len]) {
            Ok(a) => a,
            Err(_) => return,
        };

    let mut transport = match noise.into_transport_mode() {
        Ok(t) => t,
        Err(_) => return,
    };

    let enc = match ws_rx.next().await {
        Some(Ok(Message::Binary(d))) => d.to_vec(),
        _ => return,
    };
    let req_len = match transport.read_message(&enc, &mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };

    #[derive(serde::Deserialize)]
    struct RegReq {
        owner: String,
        vm_name: String,
    }
    let reg: RegReq = match serde_json::from_slice(&buf[..req_len]) {
        Ok(r) => r,
        Err(_) => return,
    };

    let client = reqwest::Client::new();
    let agent_id = uuid::Uuid::new_v4().to_string();
    let tunnel_info =
        match crate::tunnel::create_agent_tunnel(&client, &cf, &agent_id, &reg.vm_name, None).await
        {
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

    let now = chrono::Utc::now();
    state.agent_registry.lock().await.insert(
        agent_id.clone(),
        RegisteredAgent {
            agent_id,
            hostname: tunnel_info.hostname.clone(),
            vm_name: reg.vm_name,
            attestation_type: attestation.attestation_type,
            registered_at: now.to_rfc3339(),
            last_seen: now,
            status: "healthy".into(),
            deployment_count: 0,
            deployment_names: Vec::new(),
            cpu_percent: 0,
            memory_used_mb: 0,
            memory_total_mb: 0,
        },
    );

    let config = crate::noise::BootstrapConfig {
        owner: reg.owner,
        tunnel_token: tunnel_info.tunnel_token,
        hostname: tunnel_info.hostname,
        auth_public_key: state.auth_public_key_b64.clone(),
        auth_issuer: state.auth_issuer.clone(),
    };
    let json = serde_json::to_vec(&config).unwrap();
    let mut enc_resp = vec![0u8; 65535];
    if let Ok(len) = transport.write_message(&json, &mut enc_resp) {
        let _ = ws_tx
            .send(Message::Binary(enc_resp[..len].to_vec().into()))
            .await;
    }
}
