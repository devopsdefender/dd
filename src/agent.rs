//! Agent mode — runs inside an easyenclave TDX VM.
//!
//! On startup: POST `{vm_name, env_label, owner}` with a PAT bearer to
//! `$DD_CP_URL/register`, receive `{tunnel_token, hostname, agent_id,
//! jwt_secret_b64, cp_hostname}`, spawn cloudflared, then serve.
//!
//! The agent never mints its own JWTs or hosts a login page. The CP
//! issues the `dd_auth` cookie with `Domain=.{cf.domain}`; browsers
//! send it to the agent subdomain automatically, and the agent verifies
//! with the secret it received at registration.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::auth::{self, Keys};
use crate::config::Agent as Cfg;
use crate::ee::Ee;
use crate::error::{Error, Result};
use crate::html::{self, shell};
use crate::ita;
use crate::metrics;
use crate::terminal;

/// Re-mint interval. Intel ITA tokens typically expire in a few
/// minutes; refresh well before so `/health` always serves a live
/// token to the CP's collector.
const ITA_REFRESH: Duration = Duration::from_secs(180);

#[derive(Clone)]
struct St {
    cfg: Arc<Cfg>,
    ee: Arc<Ee>,
    keys: Arc<Keys>,
    hostname: String,
    cp_hostname: String,
    started: Instant,
    /// Current Intel-signed JWT. Refreshed by a background task.
    ita_token: Arc<RwLock<String>>,
}

pub async fn run() -> Result<()> {
    let cfg = Arc::new(Cfg::from_env()?);
    let ee = Arc::new(Ee::new(&cfg.ee_socket));

    let h = ee.health().await?;
    eprintln!(
        "agent: EE connected (attestation={})",
        h["attestation_type"].as_str().unwrap_or("?")
    );

    let initial_token = mint_ita(&cfg, &ee).await?;
    eprintln!("agent: ITA token minted");

    eprintln!("agent: registering with {}", cfg.cp_url);
    let b = register(&cfg, &initial_token).await?;
    eprintln!("agent: registered as {}", b.hostname);

    spawn_cloudflared(b.tunnel_token);

    let keys = Arc::new(Keys::from_b64(&b.jwt_secret_b64, &b.cp_hostname)?);
    let ita_token = Arc::new(RwLock::new(initial_token));

    // Background re-mint so /health always serves a non-expired token
    // for the CP's scrape-and-verify loop.
    {
        let cfg = cfg.clone();
        let ee = ee.clone();
        let token = ita_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(ITA_REFRESH).await;
                match mint_ita(&cfg, &ee).await {
                    Ok(t) => {
                        *token.write().await = t;
                        eprintln!("agent: ITA token refreshed");
                    }
                    Err(e) => {
                        eprintln!("agent: ITA refresh failed (keeping stale token): {e}");
                    }
                }
            }
        });
    }

    let state = St {
        cfg: cfg.clone(),
        ee,
        keys,
        hostname: b.hostname,
        cp_hostname: b.cp_hostname,
        started: Instant::now(),
        ita_token,
    };

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/workload/{id}", get(workload_page))
        .route("/session/{app}", get(session_page))
        .route("/ws/session/{app}", get(session_ws))
        .route("/deploy", post(deploy))
        .route("/exec", post(exec))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cfg.common.port);
    eprintln!("agent: listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::Internal(e.to_string()))
}

#[derive(Debug, serde::Deserialize)]
struct Bootstrap {
    tunnel_token: String,
    hostname: String,
    jwt_secret_b64: String,
    cp_hostname: String,
}

async fn register(cfg: &Cfg, ita_token: &str) -> Result<Bootstrap> {
    let http = reqwest::Client::new();
    let url = format!("{}/register", cfg.cp_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "vm_name": cfg.common.vm_name,
        "env_label": cfg.common.env_label,
        "owner": cfg.common.owner,
        "ita_token": ita_token,
    });
    let resp = http
        .post(&url)
        .bearer_auth(&cfg.pat)
        .json(&body)
        .send()
        .await
        .map_err(|e| Error::Upstream(format!("register {url}: {e}")))?;
    if !resp.status().is_success() {
        let s = resp.status();
        let b = resp.text().await.unwrap_or_default();
        return Err(Error::Upstream(format!("register {url} → {s}: {b}")));
    }
    Ok(resp.json().await?)
}

/// Mint an Intel-signed TDX attestation JWT. Fatal on any failure —
/// the agent refuses to start without a valid token.
async fn mint_ita(cfg: &Cfg, ee: &Ee) -> Result<String> {
    use base64::Engine;
    let nonce = base64::engine::general_purpose::STANDARD.encode(uuid::Uuid::new_v4().as_bytes());
    let quote_b64 = ee.attest(&nonce).await?["quote_b64"]
        .as_str()
        .ok_or_else(|| Error::Upstream("EE attest returned no quote_b64".into()))?
        .to_string();
    ita::mint(&cfg.ita.base_url, &cfg.ita.api_key, &quote_b64).await
}

fn spawn_cloudflared(token: String) {
    tokio::spawn(async move {
        eprintln!("agent: spawning cloudflared");
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
                eprintln!("agent: cloudflared exited: {status:?}");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("agent: cloudflared spawn failed: {e}");
                std::process::exit(1);
            }
        }
    });
}

// ── Routes ──────────────────────────────────────────────────────────────

async fn health(State(s): State<St>) -> Json<serde_json::Value> {
    let ee_health = s.ee.health().await.unwrap_or_default();
    let list = s.ee.list().await.unwrap_or_default();
    let deployments: Vec<String> = list["deployments"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|d| d["app_name"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let m = metrics::collect().await;
    let ita_token = s.ita_token.read().await.clone();

    Json(serde_json::json!({
        "ok": true,
        "service": "agent",
        "agent_id": s.hostname,
        "vm_name": s.cfg.common.vm_name,
        "hostname": s.hostname,
        "owner": s.cfg.common.owner,
        "attestation_type": ee_health["attestation_type"].as_str().unwrap_or("unknown"),
        "deployments": deployments,
        "deployment_count": list["deployments"].as_array().map(|a| a.len()).unwrap_or(0),
        "cpu_percent": m.cpu_pct,
        "memory_used_mb": m.mem_used_mb,
        "memory_total_mb": m.mem_total_mb,
        "nets": m.nets,
        "disks": m.disks,
        "uptime_secs": s.started.elapsed().as_secs(),
        "ita_token": ita_token,
    }))
}

async fn require_auth(
    s: &St,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
) -> std::result::Result<String, Response> {
    match auth::resolve(&s.keys, &s.cfg.common.owner, headers).await {
        Ok(login) => Ok(login),
        Err(Error::Unauthorized) => Err(auth::login_redirect(&s.cp_hostname, uri)),
        Err(e) => Err(e.into_response()),
    }
}

async fn dashboard(
    State(s): State<St>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Response {
    if let Err(r) = require_auth(&s, &headers, &uri).await {
        return r;
    }
    let m = metrics::collect().await;
    let list = s.ee.list().await.unwrap_or_default();
    let ee_health = s.ee.health().await.unwrap_or_default();
    let att = ee_health["attestation_type"].as_str().unwrap_or("unknown");

    let deployments: Vec<&serde_json::Value> = list["deployments"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();

    let mut rows = String::new();
    for d in &deployments {
        let status = d["status"].as_str().unwrap_or("idle");
        let cls = match status {
            "running" => "running",
            "deploying" => "deploying",
            "failed" | "exited" => "failed",
            _ => "idle",
        };
        let id = d["id"].as_str().unwrap_or("");
        let app = d["app_name"].as_str().unwrap_or("unnamed");
        let image = d["image"].as_str().unwrap_or("");
        let session = if status == "running" {
            format!(r#"<a href="/session/{app}">shell</a>"#)
        } else {
            r#"<span class="dim">—</span>"#.into()
        };
        rows.push_str(&format!(
            r#"<tr><td><a href="/workload/{id}">{app}</a></td><td><span class="pill {cls}">{status}</span></td><td class="dim">{image}</td><td>{session}</td></tr>"#
        ));
    }

    let table = if deployments.is_empty() {
        r#"<div class="empty">No workloads running</div>"#.to_string()
    } else {
        format!(
            r#"<table><tr><th>app</th><th>status</th><th>image</th><th>session</th></tr>{rows}</table>"#
        )
    };

    let body = format!(
        r#"<h1>{hostname}</h1>
<div class="sub">{vm} · {att}</div>
<div class="meta"><span class="ok">healthy</span> · uptime {up} · {count} workload(s)</div>
<div class="cards">
  <div class="card"><div class="label">CPU</div><div class="value green">{cpu}%</div></div>
  <div class="card"><div class="label">Memory</div><div class="value blue">{mu} / {mt}</div></div>
  <div class="card"><div class="label">Load 1m</div><div class="value mauve">{load:.2}</div></div>
</div>
<div class="section">Workloads</div>{table}"#,
        hostname = html::escape(&s.hostname),
        vm = html::escape(&s.cfg.common.vm_name),
        att = html::escape(att),
        up = metrics::format_duration_secs(s.started.elapsed().as_secs()),
        count = deployments.len(),
        cpu = m.cpu_pct,
        mu = metrics::format_bytes_mb(m.mem_used_mb),
        mt = metrics::format_bytes_mb(m.mem_total_mb),
        load = m.load_1m,
    );

    Html(shell(
        &format!("DD — {}", s.cfg.common.vm_name),
        &html::nav(&[("Dashboard", "/", true)]),
        &body,
    ))
    .into_response()
}

async fn workload_page(
    State(s): State<St>,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Result<Response> {
    if let Err(r) = require_auth(&s, &headers, &uri).await {
        return Ok(r);
    }
    let list = s.ee.list().await?;
    let deployments: Vec<&serde_json::Value> = list["deployments"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let d = deployments
        .iter()
        .find(|d| d["id"].as_str() == Some(id.as_str()))
        .ok_or(Error::NotFound)?;
    let app = d["app_name"].as_str().unwrap_or("unnamed");
    let status = d["status"].as_str().unwrap_or("unknown");
    let image = d["image"].as_str().unwrap_or("");
    let started = d["started_at"].as_str().unwrap_or("");
    let error = d["error_message"].as_str().unwrap_or("");

    let logs = s.ee.logs(&id).await.unwrap_or_default();
    let log_text = logs["lines"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(html::escape)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();

    let err_row = if error.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="row"><span>Error</span><span style="color:#f38ba8">{}</span></div>"#,
            html::escape(error)
        )
    };
    let session_link = if status == "running" {
        format!(
            r#"<p style="margin:12px 0"><a href="/session/{app}">Open terminal session</a></p>"#
        )
    } else {
        String::new()
    };

    let body = format!(
        r#"<div class="back"><a href="/">← dashboard</a></div>
<h1>{app}</h1>
<div class="sub">{id}</div>
<div class="card">
  <div class="row"><span>Status</span><span class="pill {cls}">{status}</span></div>
  <div class="row"><span>Image</span><span>{image}</span></div>
  <div class="row"><span>Started</span><span>{started}</span></div>
  {err_row}
</div>
{session_link}
<div class="section">Logs</div>
<pre style="max-height:60vh">{logs}</pre>"#,
        app = html::escape(app),
        id = html::escape(&id),
        cls = match status {
            "running" => "running",
            "deploying" => "deploying",
            "failed" | "exited" => "failed",
            _ => "idle",
        },
        status = html::escape(status),
        image = html::escape(image),
        started = html::escape(started),
        err_row = err_row,
        session_link = session_link,
        logs = if log_text.is_empty() {
            "<span class=\"dim\">No logs</span>".into()
        } else {
            log_text
        },
    );

    Ok(Html(shell(
        &format!("DD — {app}"),
        &html::nav(&[("Dashboard", "/", false)]),
        &body,
    ))
    .into_response())
}

async fn session_page(
    State(s): State<St>,
    Path(app): Path<String>,
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Response {
    if let Err(r) = require_auth(&s, &headers, &uri).await {
        return r;
    }
    let ws = format!("/ws/session/{}", urlencoding::encode(&app));
    Html(terminal::page(&app, &ws)).into_response()
}

async fn deploy(
    State(s): State<St>,
    headers: HeaderMap,
    Json(spec): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    auth::resolve(&s.keys, &s.cfg.common.owner, &headers).await?;
    Ok(Json(s.ee.deploy(spec).await?))
}

#[derive(Debug, Deserialize)]
struct ExecReq {
    cmd: Vec<String>,
    #[serde(default = "default_exec_timeout")]
    timeout_secs: u64,
}
fn default_exec_timeout() -> u64 {
    60
}

async fn exec(
    State(s): State<St>,
    headers: HeaderMap,
    Json(req): Json<ExecReq>,
) -> Result<Json<serde_json::Value>> {
    auth::resolve(&s.keys, &s.cfg.common.owner, &headers).await?;
    Ok(Json(s.ee.exec(&req.cmd, req.timeout_secs).await?))
}

async fn session_ws(
    State(s): State<St>,
    Path(app): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    auth::resolve(&s.keys, &s.cfg.common.owner, &headers).await?;
    let _ = app;
    let vm = s.cfg.common.vm_name.clone();
    let ee = s.ee.clone();
    Ok(ws.on_upgrade(move |socket| async move {
        terminal::bridge(socket, ee, &vm).await;
    }))
}
