use axum::extract::{OriginalUri, Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};

use crate::auth::require_browser_auth;
use crate::html::{format_uptime, nav_bar, page_shell};
use crate::state::WebState;

/// GET / -- fleet dashboard showing all agents from local store + federated peers.
pub async fn fleet_dashboard(
    State(state): State<WebState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, Response> {
    if !state.config.owner.is_empty() {
        require_browser_auth(&state, &headers, &uri).await?;
    }

    Ok(fleet_dashboard_html(&state).await.into_response())
}

async fn fleet_dashboard_html(state: &WebState) -> Html<String> {
    // Merge local agents with peer agents
    let local_agents = state.agents.lock().await;
    let mut all_agents: Vec<_> = local_agents.values().cloned().collect();
    drop(local_agents);

    // Fetch from peers
    let peer_agents = crate::federate::query_peers(state).await;
    // Merge: peer agents whose hostname is not already in local store
    let local_hostnames: std::collections::HashSet<String> =
        all_agents.iter().map(|a| a.hostname.clone()).collect();
    for pa in peer_agents {
        if !local_hostnames.contains(&pa.hostname) {
            all_agents.push(pa);
        }
    }

    let env = &state.config.env_label;
    let now = chrono::Utc::now();

    let mut rows = String::new();
    for a in &all_agents {
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

    let agents_count = all_agents.len();
    let agent_table = if all_agents.is_empty() {
        r#"<div class="empty">No agents discovered</div>"#.to_string()
    } else {
        format!(
            r#"<table><tr><th>hostname</th><th>vm</th><th>status</th><th>attestation</th><th>workloads</th><th>cpu</th><th>memory</th><th>last seen</th></tr>{rows}</table>"#
        )
    };

    let peer_info = if state.config.peers.is_empty() {
        String::new()
    } else {
        format!(" &middot; {} peer(s)", state.config.peers.len())
    };

    let content = format!(
        r#"<h1>DevOps Defender</h1>
<div class="sub">{env} fleet &middot; {hostname}</div>
<div class="meta"><span class="ok">healthy</span> &middot; uptime {uptime} &middot; {count} agent(s){peer_info}</div>
<div class="section">Agents</div>
{agent_table}"#,
        env = env,
        hostname = state.config.hostname,
        uptime = uptime_str,
        count = agents_count,
        agent_table = agent_table,
        peer_info = peer_info,
    );

    Html(page_shell(&format!("DD Fleet -- {env}"), &nav, &content))
}

/// GET /agent/{id} -- agent detail page
pub async fn agent_detail(
    Path(agent_id): Path<String>,
    State(state): State<WebState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, Response> {
    if !state.config.owner.is_empty() {
        require_browser_auth(&state, &headers, &uri).await?;
    }

    let agents = state.agents.lock().await;
    let Some(a) = agents.get(&agent_id) else {
        return Ok((axum::http::StatusCode::NOT_FOUND, "agent not found").into_response());
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
        last_seen = last_seen,
        cpu = a.cpu_percent,
        mem = mem_str,
        workloads = workloads,
    );

    Ok(Html(page_shell(
        &format!("{} -- DD Fleet", a.hostname),
        &nav,
        &content,
    ))
    .into_response())
}
