//! Control-plane mode — fleet registry, agent registration, dashboard, shell.
//!
//! One HTTP port (`$DD_PORT`, default 8080) behind the CP's own CF tunnel.
//! On startup we: self-provision a CF tunnel at `$DD_HOSTNAME`, spawn
//! cloudflared, STONITH any older CP (by `dd-{env}-cp-*` name prefix),
//! start the self-watchdog and collector, then serve the router.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use crate::auth::{self, Keys};
use crate::cf;
use crate::collector::{self, Store};
use crate::config::Cp as Cfg;
use crate::ee::Ee;
use crate::error::{Error, Result};
use crate::html::{self, shell};
use crate::ita;
use crate::metrics;
use crate::stonith;
use crate::terminal;

/// Re-mint interval for the CP's own ITA token. The CP isn't scraped
/// by its own collector (different tunnel prefix), so a background
/// task is the only thing keeping the `control-plane` entry's claims
/// fresh on the dashboard.
const ITA_REFRESH: Duration = Duration::from_secs(180);

#[derive(Clone)]
struct St {
    cfg: Arc<Cfg>,
    ee: Arc<Ee>,
    keys: Arc<Keys>,
    store: Store,
    started: Instant,
    verifier: Arc<ita::Verifier>,
    /// The CP's own ITA token. Refreshed by a background task.
    cp_ita_token: Arc<RwLock<String>>,
}

pub async fn run() -> Result<()> {
    let cfg = Arc::new(Cfg::from_env()?);
    let ee = Arc::new(Ee::new("/var/lib/easyenclave/agent.sock"));

    eprintln!("cp: self-provisioning tunnel for {}", cfg.hostname);
    let http = reqwest::Client::new();
    let self_name = cf::cp_tunnel_name(&cfg.common.env_label);
    let tunnel = match cf::create(&http, &cfg.cf, &self_name, &cfg.hostname).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cp: self-register failed: {e}");
            stonith::poweroff();
        }
    };
    eprintln!("cp: self tunnel {} → {}", tunnel.id, tunnel.hostname);

    spawn_cloudflared(tunnel.token.clone());

    {
        let http = http.clone();
        let cf = cfg.cf.clone();
        let id = tunnel.id.clone();
        let env = cfg.common.env_label.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            stonith::kill_old_tunnels(&http, &cf, &id, &env).await;
        });
    }

    tokio::spawn(stonith::self_watchdog(cfg.cf.clone(), tunnel.id.clone()));

    let store: Store = Arc::new(Mutex::new(HashMap::new()));

    let keys = Arc::new(Keys::fresh(&cfg.hostname));

    // ITA verifier — required.
    let verifier = ita::Verifier::new(cfg.ita.jwks_url.clone(), cfg.ita.issuer.clone());
    eprintln!("cp: ITA verifier enabled (issuer={})", cfg.ita.issuer);

    // Mint + verify our own ITA token. Any failure is fatal —
    // attestation is mandatory.
    let initial_token = match mint_cp_ita(&cfg, &ee).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cp: ITA mint failed: {e}");
            stonith::poweroff();
        }
    };
    let cp_claims = match verifier.verify(&initial_token).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cp: ITA self-verify failed: {e}");
            stonith::poweroff();
        }
    };
    eprintln!(
        "cp: own ITA verified mrtd={} tcb={}",
        cp_claims.mrtd.as_deref().unwrap_or("?"),
        cp_claims.tcb_status.as_deref().unwrap_or("?")
    );
    let cp_ita_token = Arc::new(RwLock::new(initial_token));

    // Seed the CP into the store before the collector starts ticking.
    // The refresh loop below will keep these numbers current every
    // ITA_REFRESH ticks; we fill them once at startup so the first
    // render isn't all zeros while the refresh loop sleeps.
    let cp_m = metrics::collect().await;
    store.lock().await.insert(
        "control-plane".into(),
        collector::Agent {
            agent_id: "control-plane".into(),
            hostname: cfg.hostname.clone(),
            vm_name: format!("dd-{}-cp", cfg.common.env_label),
            attestation_type: "tdx".into(),
            status: "healthy".into(),
            last_seen: chrono::Utc::now(),
            deployment_count: 0,
            deployment_names: Vec::new(),
            cpu_percent: cp_m.cpu_pct,
            memory_used_mb: cp_m.mem_used_mb,
            memory_total_mb: cp_m.mem_total_mb,
            nets: cp_m.nets,
            disks: cp_m.disks,
            ita: cp_claims,
        },
    );

    // Background re-mint of the CP's own ITA token. Also re-verifies
    // and updates the `control-plane` store entry so the fleet card
    // doesn't show "Expired".
    {
        let cfg = cfg.clone();
        let ee = ee.clone();
        let verifier = verifier.clone();
        let token = cp_ita_token.clone();
        let store = store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(ITA_REFRESH).await;
                let fresh = match mint_cp_ita(&cfg, &ee).await {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("cp: own ITA refresh mint failed: {e}");
                        continue;
                    }
                };
                let claims = match verifier.verify(&fresh).await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("cp: own ITA refresh verify failed: {e}");
                        continue;
                    }
                };
                *token.write().await = fresh;
                // Also refresh live system metrics on the CP's own
                // store entry — the collector scrapes other tunnels,
                // not itself, so without this the /agent/control-plane
                // detail page would show empty disks/nets/cpu forever.
                let m = crate::metrics::collect().await;
                if let Some(cp) = store.lock().await.get_mut("control-plane") {
                    cp.ita = claims;
                    cp.last_seen = chrono::Utc::now();
                    cp.cpu_percent = m.cpu_pct;
                    cp.memory_used_mb = m.mem_used_mb;
                    cp.memory_total_mb = m.mem_total_mb;
                    cp.nets = m.nets;
                    cp.disks = m.disks;
                }
                eprintln!("cp: own ITA token refreshed");
            }
        });
    }

    // Start the collector with the verifier. It re-verifies each
    // scraped agent's ita_token, so expired / revoked / unsigned
    // agents drop off the dashboard automatically.
    tokio::spawn(collector::run(
        store.clone(),
        cfg.cf.clone(),
        cfg.common.env_label.clone(),
        cfg.hostname.clone(),
        ee.clone(),
        verifier.clone(),
        Duration::from_secs(cfg.scrape_interval_secs),
    ));

    let state = St {
        cfg: cfg.clone(),
        ee,
        keys,
        store,
        started: Instant::now(),
        verifier,
        cp_ita_token,
    };

    let app = Router::new()
        .route("/", get(fleet))
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/agent/{id}", get(agent_detail))
        .route("/agent/{id}/logs/{app}", get(agent_logs))
        .route("/api/agents", get(api_agents))
        .route("/cp/attest", get(cp_attest))
        .route("/cp/ita", get(cp_ita))
        .route("/cp/shell", get(shell_page))
        .route("/cp/ws/shell", get(shell_ws))
        .route("/auth/pat", get(pat_form).post(pat_submit))
        .route("/auth/logout", get(logout))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cfg.common.port);
    eprintln!("cp: listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::Internal(e.to_string()))
}

fn spawn_cloudflared(token: String) {
    tokio::spawn(async move {
        eprintln!("cp: spawning cloudflared");
        match tokio::process::Command::new("cloudflared")
            .args([
                "tunnel",
                "--no-autoupdate",
                "--metrics=",
                "run",
                "--token",
                &token,
            ])
            .spawn()
        {
            Ok(mut child) => {
                let status = child.wait().await;
                eprintln!("cp: cloudflared exited: {status:?} — poweroff");
                stonith::poweroff();
            }
            Err(e) => {
                eprintln!("cp: cloudflared spawn failed: {e} — poweroff");
                stonith::poweroff();
            }
        }
    });
}

// ── Routes ──────────────────────────────────────────────────────────────

async fn health(State(s): State<St>) -> Json<serde_json::Value> {
    let agents = s.store.lock().await;
    Json(serde_json::json!({
        "ok": true,
        "service": "cp",
        "hostname": s.cfg.hostname,
        "env": s.cfg.common.env_label,
        "uptime_secs": s.started.elapsed().as_secs(),
        "agent_count": agents.len(),
        "healthy_count": agents.values().filter(|a| a.status == "healthy").count(),
    }))
}

#[derive(Debug, Deserialize)]
struct RegisterReq {
    vm_name: String,
    env_label: String,
    owner: String,
    ita_token: String,
}

/// POST /register — agent presents a GitHub PAT belonging to DD_OWNER;
/// we verify, optionally verify its ITA token, create an agent tunnel,
/// and return the tunnel token + the JWT signing secret (so the agent
/// can verify CP-issued cookies).
async fn register(
    State(s): State<St>,
    headers: HeaderMap,
    Json(req): Json<RegisterReq>,
) -> Result<Json<serde_json::Value>> {
    let pat = auth::bearer(&headers).ok_or(Error::Unauthorized)?;
    let login = auth::verify_pat(&pat, &s.cfg.common.owner).await?;

    if req.owner != s.cfg.common.owner {
        return Err(Error::BadRequest(format!(
            "owner mismatch: got {} expected {}",
            req.owner, s.cfg.common.owner
        )));
    }
    if req.env_label != s.cfg.common.env_label {
        return Err(Error::BadRequest(format!(
            "env_label mismatch: got {} expected {}",
            req.env_label, s.cfg.common.env_label
        )));
    }

    // ITA is mandatory. Any failure → 401.
    let ita_claims = s.verifier.verify(&req.ita_token).await?;
    eprintln!(
        "cp: ITA verified for {} mrtd={} tcb={}",
        req.vm_name,
        ita_claims.mrtd.as_deref().unwrap_or("?"),
        ita_claims.tcb_status.as_deref().unwrap_or("?")
    );

    let http = reqwest::Client::new();
    let name = cf::agent_tunnel_name(&s.cfg.common.env_label);
    let agent_hostname = format!("{name}.{}", s.cfg.cf.domain);
    let tunnel = cf::create(&http, &s.cfg.cf, &name, &agent_hostname).await?;

    // Seed the store so the dashboard shows the agent before the first
    // collector tick. Also evict any prior entries with the same
    // vm_name — a relaunched VM registers a new agent_id/hostname, but
    // the stale old one hangs around until the collector's dead
    // threshold (5 min). During that window `/api/agents` returns
    // duplicates and host-side scripts can pick the dead hostname.
    let now = chrono::Utc::now();
    {
        let mut store = s.store.lock().await;
        let stale: Vec<String> = store
            .iter()
            .filter(|(id, a)| a.vm_name == req.vm_name && id.as_str() != name)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            store.remove(&id);
        }
        store.insert(
            name.clone(),
            collector::Agent {
                agent_id: name.clone(),
                hostname: tunnel.hostname.clone(),
                vm_name: req.vm_name.clone(),
                attestation_type: "tdx".into(),
                status: "healthy".into(),
                last_seen: now,
                deployment_count: 0,
                deployment_names: Vec::new(),
                cpu_percent: 0,
                memory_used_mb: 0,
                memory_total_mb: 0,
                nets: Vec::new(),
                disks: Vec::new(),
                ita: ita_claims,
            },
        );
    }

    eprintln!(
        "cp: registered {} as {} (login={login})",
        req.vm_name, agent_hostname
    );

    Ok(Json(serde_json::json!({
        "tunnel_token": tunnel.token,
        "hostname": tunnel.hostname,
        "agent_id": name,
        "jwt_secret_b64": s.keys.secret_b64,
        "cp_hostname": s.cfg.hostname,
    })))
}

/// Mint the CP's own ITA token at startup. Fatal on any failure —
/// the CP refuses to start without proving its own TDX measurement.
async fn mint_cp_ita(cfg: &Cfg, ee: &Ee) -> Result<String> {
    use base64::Engine;
    let nonce = base64::engine::general_purpose::STANDARD.encode(uuid::Uuid::new_v4().as_bytes());
    let quote_b64 = ee.attest(&nonce).await?["quote_b64"]
        .as_str()
        .ok_or_else(|| Error::Upstream("EE attest returned no quote_b64".into()))?
        .to_string();
    ita::mint(&cfg.ita.base_url, &cfg.ita.api_key, &quote_b64).await
}

// ── Fleet dashboard ──────────────────────────────────────────────────────

async fn fleet(
    State(s): State<St>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Response {
    if let Err(r) = require_auth(&s, &headers, &uri).await {
        return r;
    }

    let agents = s.store.lock().await.clone();
    let mut rows = String::new();
    let mut by_id: Vec<_> = agents.into_iter().collect();
    by_id.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, a) in &by_id {
        let mem = if a.memory_total_mb > 0 {
            format!("{}/{} MB", a.memory_used_mb, a.memory_total_mb)
        } else {
            "—".into()
        };
        rows.push_str(&format!(
            r#"<tr><td><a href="/agent/{id}">{vm}</a></td>
<td><span class="pill {st}">{st}</span></td><td>{att}</td>
<td>{cpu}%</td><td>{mem}</td><td>{n}</td>
<td class="dim">{host}</td></tr>"#,
            id = html::escape(&a.agent_id),
            vm = html::escape(&a.vm_name),
            st = html::escape(&a.status),
            att = html::escape(&a.attestation_type),
            cpu = a.cpu_percent,
            n = a.deployment_count,
            host = html::escape(&a.hostname),
        ));
    }

    let table = if by_id.is_empty() {
        r#"<div class="empty">No agents registered</div>"#.to_string()
    } else {
        format!(
            r#"<table><tr><th>vm</th><th>status</th><th>att</th><th>cpu</th><th>mem</th><th>wl</th><th>host</th></tr>{rows}</table>"#
        )
    };

    Html(shell(
        "DD Fleet",
        &html::nav(&[("Fleet", "/", true)]),
        &format!(
            r#"<h1>Fleet</h1><div class="sub">{host} · env {env} · {n} agent(s)</div>{table}"#,
            host = html::escape(&s.cfg.hostname),
            env = html::escape(&s.cfg.common.env_label),
            n = by_id.len(),
        ),
    ))
    .into_response()
}

/// GET /api/agents — JSON list of
/// `{agent_id, vm_name, hostname, status, last_seen}`.
/// Used by the Local Agents workflow's HTTPS step to discover a
/// specific agent's tunnel hostname after it re-registers.
async fn api_agents(
    State(s): State<St>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<Json<Vec<serde_json::Value>>> {
    if require_auth(&s, &headers, &uri).await.is_err() {
        return Err(Error::Unauthorized);
    }
    let agents = s.store.lock().await.clone();
    Ok(Json(
        agents
            .into_values()
            .map(|a| {
                serde_json::json!({
                    "agent_id": a.agent_id,
                    "vm_name": a.vm_name,
                    "hostname": a.hostname,
                    "status": a.status,
                    "last_seen": a.last_seen.to_rfc3339(),
                })
            })
            .collect(),
    ))
}

async fn agent_detail(
    State(s): State<St>,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Response {
    if let Err(r) = require_auth(&s, &headers, &uri).await {
        return r;
    }
    let agent = s.store.lock().await.get(&id).cloned();
    let Some(a) = agent else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Html(shell("Not found", "", "<h1>Not found</h1>")),
        )
            .into_response();
    };

    let is_cp = a.agent_id == "control-plane";
    let mut workloads = String::new();
    for w in &a.deployment_names {
        let link = if is_cp {
            format!(
                r#"<a href="/agent/{id}/logs/{w}">logs</a>"#,
                id = html::escape(&a.agent_id),
                w = html::escape(w)
            )
        } else {
            String::new()
        };
        workloads.push_str(&format!(
            r#"<tr><td>{w}</td><td>{link}</td></tr>"#,
            w = html::escape(w)
        ));
    }
    let wl_table = if a.deployment_names.is_empty() {
        r#"<div class="empty">No workloads</div>"#.to_string()
    } else {
        format!(r#"<table><tr><th>workload</th><th></th></tr>{workloads}</table>"#)
    };

    let ita_card = {
        let c = &a.ita;
        let tcb = c.tcb_status.as_deref().unwrap_or("?");
        let tcb_cls = match tcb {
            "UpToDate" | "OK" => "running",
            "OutOfDate" | "SWHardeningNeeded" | "ConfigurationNeeded" => "deploying",
            "Revoked" | "Invalid" => "failed",
            _ => "idle",
        };
        let mrtd_short = c
            .mrtd
            .as_deref()
            .map(|m| if m.len() > 16 { &m[..16] } else { m })
            .unwrap_or("?");
        let delta = c.exp - chrono::Utc::now().timestamp();
        let expiry = if delta > 0 {
            format!("in {}m", delta / 60)
        } else {
            "expired".to_string()
        };
        format!(
            r#"<div class="section">Intel Trust Authority</div>
<div class="card">
  <div class="row"><span>TCB status</span><span class="pill {cls}">{tcb}</span></div>
  <div class="row"><span>MRTD</span><span class="dim">{mrtd}…</span></div>
  <div class="row"><span>Attester type</span><span>{typ}</span></div>
  <div class="row"><span>Expires</span><span>{exp}</span></div>
</div>"#,
            cls = tcb_cls,
            tcb = html::escape(tcb),
            mrtd = html::escape(mrtd_short),
            typ = html::escape(c.attester_type.as_deref().unwrap_or("?")),
            exp = expiry,
        )
    };

    let extra = if is_cp {
        r#"<p><a href="/cp/shell">open CP shell</a> · <a href="/cp/attest">raw quote</a> · <a href="/cp/ita">ITA token</a></p>"#
            .to_string()
    } else {
        format!(
            r#"<p><a href="https://{h}/">open agent dashboard ↗</a></p>"#,
            h = html::escape(&a.hostname)
        )
    };

    let disks_table = if a.disks.is_empty() {
        String::new()
    } else {
        let mut rows = String::new();
        for d in &a.disks {
            rows.push_str(&format!(
                "<tr><td>{m}</td><td class=\"dim\">{fs}</td><td>{u}/{t} GB</td></tr>",
                m = html::escape(&d.mount),
                fs = html::escape(&d.fstype),
                u = d.used_gb,
                t = d.total_gb,
            ));
        }
        format!(
            r#"<div class="section">Disks</div><table><tr><th>mount</th><th>fs</th><th>used</th></tr>{rows}</table>"#
        )
    };

    let nets_table = if a.nets.is_empty() {
        String::new()
    } else {
        let mut rows = String::new();
        for n in &a.nets {
            rows.push_str(&format!(
                "<tr><td>{i}</td><td>{rx}</td><td>{tx}</td></tr>",
                i = html::escape(&n.iface),
                rx = metrics::format_bytes_si(n.rx_bytes),
                tx = metrics::format_bytes_si(n.tx_bytes),
            ));
        }
        format!(
            r#"<div class="section">Network</div><table><tr><th>iface</th><th>rx</th><th>tx</th></tr>{rows}</table>"#
        )
    };

    Html(shell(
        &format!("DD — {}", a.vm_name),
        &html::nav(&[("Fleet", "/", false)]),
        &format!(
            r#"<div class="back"><a href="/">← fleet</a></div>
<h1>{vm}</h1><div class="sub">{id} · {host}</div>
<div class="card">
  <div class="row"><span>Status</span><span class="pill {st}">{st}</span></div>
  <div class="row"><span>Attestation</span><span>{att}</span></div>
  <div class="row"><span>Last seen</span><span>{ls}</span></div>
  <div class="row"><span>CPU</span><span>{cpu}%</span></div>
  <div class="row"><span>Memory</span><span>{mu}/{mt} MB</span></div>
</div>
{disks_table}
{nets_table}
{ita_card}
<div class="section">Workloads</div>{wl_table}
{extra}"#,
            vm = html::escape(&a.vm_name),
            id = html::escape(&a.agent_id),
            host = html::escape(&a.hostname),
            st = html::escape(&a.status),
            att = html::escape(&a.attestation_type),
            ls = a.last_seen.to_rfc3339(),
            cpu = a.cpu_percent,
            mu = a.memory_used_mb,
            mt = a.memory_total_mb,
            disks_table = disks_table,
            nets_table = nets_table,
            ita_card = ita_card,
        ),
    ))
    .into_response()
}

/// GET /agent/control-plane/logs/{app} — show logs for a CP workload via the
/// local easyenclave socket. For other agents we'd proxy to their dashboard;
/// today the detail page links directly there instead.
async fn agent_logs(
    State(s): State<St>,
    Path((id, app)): Path<(String, String)>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Response {
    if let Err(r) = require_auth(&s, &headers, &uri).await {
        return r;
    }
    if id != "control-plane" {
        return Error::NotFound.into_response();
    }
    // Find the workload by app_name.
    let list = s.ee.list().await.unwrap_or_default();
    let dep_id = list["deployments"]
        .as_array()
        .and_then(|a| a.iter().find(|d| d["app_name"].as_str() == Some(&app)))
        .and_then(|d| d["id"].as_str())
        .map(String::from);
    let Some(dep_id) = dep_id else {
        return Error::NotFound.into_response();
    };
    let logs = s.ee.logs(&dep_id).await.unwrap_or_default();
    let text = logs["lines"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(html::escape)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    Html(shell(
        &format!("{app} logs"),
        &html::nav(&[("Fleet", "/", false)]),
        &format!(
            r#"<div class="back"><a href="/agent/control-plane">← control-plane</a></div>
<h1>{app}</h1><div class="sub">auto-refresh 2s</div>
<pre style="max-height:80vh">{text}</pre>
<script>setTimeout(() => location.reload(), 2000);</script>"#,
            app = html::escape(&app)
        ),
    ))
    .into_response()
}

async fn cp_attest(
    State(s): State<St>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<Json<serde_json::Value>> {
    if require_auth(&s, &headers, &uri).await.is_err() {
        return Err(Error::Unauthorized);
    }
    // EE base64-decodes the nonce; synthesize one if the caller didn't
    // pass one (browser-click from the dashboard).
    let nonce = q
        .get("nonce")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(uuid::Uuid::new_v4().as_bytes())
        });
    Ok(Json(s.ee.attest(&nonce).await?))
}

/// GET /cp/ita — the CP's own ITA token, minted + self-verified at
/// startup. External verifiers can confirm the CP VM's TDX measurement
/// by decoding it against Intel's JWKS.
async fn cp_ita(
    State(s): State<St>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<Json<serde_json::Value>> {
    if require_auth(&s, &headers, &uri).await.is_err() {
        return Err(Error::Unauthorized);
    }
    let token = s.cp_ita_token.read().await.clone();
    let claims = s.verifier.verify(&token).await?;
    Ok(Json(serde_json::json!({
        "token": token,
        "claims": claims,
    })))
}

async fn shell_page(
    State(s): State<St>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Response {
    if let Err(r) = require_auth(&s, &headers, &uri).await {
        return r;
    }
    Html(terminal::page("cp", "/cp/ws/shell")).into_response()
}

async fn shell_ws(
    State(s): State<St>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    auth::resolve(&s.keys, &s.cfg.common.owner, &headers).await?;
    let ee = s.ee.clone();
    let vm = format!("dd-{}-cp", s.cfg.common.env_label);
    Ok(ws.on_upgrade(move |socket| async move {
        terminal::bridge(socket, ee, &vm).await;
    }))
}

// ── Auth routes ─────────────────────────────────────────────────────────

async fn require_auth(
    s: &St,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
) -> std::result::Result<String, Response> {
    match auth::resolve(&s.keys, &s.cfg.common.owner, headers).await {
        Ok(login) => Ok(login),
        Err(Error::Unauthorized) => Err(auth::login_redirect_local(uri)),
        Err(e) => Err(e.into_response()),
    }
}

#[derive(Debug, Deserialize)]
struct NextQ {
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PatF {
    pat: String,
    next: Option<String>,
}

async fn pat_form(Query(q): Query<NextQ>) -> Html<String> {
    let next = auth::sanitize_next(q.next.as_deref());
    Html(shell(
        "Sign in — DD",
        "",
        &format!(
            r#"<h1>Sign in</h1>
<div class="sub">Paste a GitHub PAT (run <code>gh auth token</code>).</div>
<form method="POST" action="/auth/pat" style="max-width:480px">
  <input type="hidden" name="next" value="{next}">
  <input type="password" name="pat" placeholder="ghp_... or ghu_..." autofocus autocomplete="off">
  <p></p>
  <button type="submit">Sign in</button>
</form>"#,
            next = html::escape(&next)
        ),
    ))
}

async fn pat_submit(State(s): State<St>, Form(f): Form<PatF>) -> Response {
    let next = auth::sanitize_next(f.next.as_deref());
    let pat = f.pat.trim();
    if pat.is_empty() {
        return Redirect::to(&format!("/auth/pat?next={}", urlencoding::encode(&next)))
            .into_response();
    }
    let Ok(login) = auth::verify_pat(pat, &s.cfg.common.owner).await else {
        return Redirect::to(&format!("/auth/pat?next={}", urlencoding::encode(&next)))
            .into_response();
    };
    let Ok(jwt) = s.keys.mint(&login) else {
        return Error::Internal("mint".into()).into_response();
    };
    auth::with_cookie(
        Redirect::to(&next),
        auth::cookie(
            auth::AUTH_COOKIE,
            &jwt,
            Some(&s.cfg.cf.domain),
            auth::COOKIE_TTL.as_secs(),
        ),
    )
}

async fn logout(State(s): State<St>) -> Response {
    auth::with_cookie(
        Redirect::to("/auth/pat"),
        auth::cookie(auth::AUTH_COOKIE, "", Some(&s.cfg.cf.domain), 0),
    )
}
