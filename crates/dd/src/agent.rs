//! Agent mode — runs inside an easyenclave TDX VM.
//!
//! On startup: POST `{vm_name, env_label, owner, ita_token}` to
//! `$DD_CP_URL/register` (no auth — ITA attestation is the gate;
//! the path is exempt from CF Access via a bypass app). The CP
//! responds with `{tunnel_token, hostname, agent_id, cp_hostname}`.
//!
//! Auth after registration:
//!   - Browser routes (`/`, `/workload/*`) are behind CF Access with
//!     the same human policy as the CP dashboard.
//!   - Terminal is a separate `bastion` workload published on
//!     `block.<hostname>` — block-aware web terminal (persistent
//!     sessions + OSC 133 command history), not tied to any
//!     deployment. See https://github.com/devopsdefender/bastion.
//!   - `/deploy` and `/exec` are CF-Access-bypassed and gated in-code
//!     by a GitHub Actions OIDC token — any CI workflow in the
//!     `DD_OWNER` org can call them by presenting its per-job OIDC
//!     JWT as `Authorization: Bearer …`.
//!   - Agent → CP `/ingress/replace` calls include the agent's fresh
//!     ITA token in the body; the CP verifies it against Intel.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::config::Agent as Cfg;
use crate::ee::Ee;
use crate::error::{Error, Result};
use crate::gh_oidc;
use crate::html::{self, shell};
use crate::ita;
use crate::metrics;

/// Re-mint interval. Intel ITA tokens typically expire in a few
/// minutes; refresh well before so `/health` always serves a live
/// token to the CP's collector.
const ITA_REFRESH: Duration = Duration::from_secs(180);

#[derive(Clone)]
struct St {
    cfg: Arc<Cfg>,
    ee: Arc<Ee>,
    hostname: String,
    /// Tunnel name returned by the CP at /register — stable for the
    /// life of this agent's tunnel. The /ingress/replace call on the
    /// CP keys off this to look up the tunnel_id.
    agent_id: String,
    started: Instant,
    /// Current Intel-signed JWT. Refreshed by a background task.
    ita_token: Arc<RwLock<String>>,
    /// Live set of per-workload ingress rules this agent has asked
    /// the CP to publish. Seeded from boot `cfg.extra_ingress`;
    /// appended each time a POSTed workload declares `expose`. The
    /// agent forwards the full list on every /ingress/replace call
    /// so the CP's PUT is a straight replacement.
    extras: Arc<RwLock<Vec<(String, u16)>>>,
    /// Verifier for GitHub Actions OIDC JWTs — the auth on /deploy
    /// and /exec. CI workflows in the DD_OWNER org can call them
    /// without any shared secret; anyone else is denied at claim
    /// check.
    gh: Arc<gh_oidc::Verifier>,
    /// Long-term Noise static keypair for m2m RPC. `None` when
    /// `DD_NOISE_KEY_DIR` isn't set or the key couldn't be loaded.
    noise_key: Option<Arc<dd_common::noise_static::NoiseStatic>>,
    /// CP's pinned pubkey, learned at registration and persisted on
    /// disk. `None` during the migration window where the CP side
    /// hasn't been given a key yet.
    cp_noise_pubkey: Option<[u8; 32]>,
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

    // Load or mint the agent's long-term Noise static keypair if a
    // dir is configured. During the m2m migration window this is
    // optional — an agent without a key registers as before and the
    // CP skips pinning it.
    let noise_key: Option<Arc<dd_common::noise_static::NoiseStatic>> =
        match std::env::var("DD_NOISE_KEY_DIR")
            .ok()
            .filter(|s| !s.is_empty())
        {
            Some(dir) => match crate::noise_m2m::load_static(std::path::Path::new(&dir)) {
                Ok(k) => {
                    eprintln!(
                        "agent: noise static key {:?} ({}…)",
                        k.source(),
                        &k.public_hex()[..16]
                    );
                    Some(k)
                }
                Err(e) => {
                    eprintln!("agent: noise key load failed at {dir}: {e}");
                    None
                }
            },
            None => None,
        };
    let noise_pubkey_hex = noise_key.as_ref().map(|k| k.public_hex());

    eprintln!("agent: registering with {}", cfg.cp_url);
    let b = register(&cfg, &initial_token, noise_pubkey_hex.as_deref()).await?;
    eprintln!("agent: registered as {}", b.hostname);

    // Pin the CP's pubkey for future m2m handshakes. Silently ignored
    // if the CP didn't advertise one (migration window).
    let mut cp_noise_pubkey: Option<[u8; 32]> = None;
    if let (Some(hex), Some(dir)) = (
        b.cp_noise_pubkey_hex.as_deref(),
        std::env::var("DD_NOISE_KEY_DIR")
            .ok()
            .filter(|s| !s.is_empty()),
    ) {
        match crate::noise_m2m::decode_pubkey(hex) {
            Ok(pk) => {
                cp_noise_pubkey = Some(pk);
                if let Err(e) = crate::noise_m2m::save_cp_pubkey(std::path::Path::new(&dir), &pk) {
                    eprintln!("agent: save CP noise pubkey: {e}");
                } else {
                    eprintln!(
                        "agent: pinned CP noise pubkey ({}…)",
                        &hex[..hex.len().min(16)]
                    );
                }
            }
            Err(e) => eprintln!("agent: CP noise pubkey decode: {e}"),
        }
    }
    // Fall back to the on-disk cache if the CP didn't advertise one
    // this boot but did previously.
    if cp_noise_pubkey.is_none() {
        if let Some(dir) = std::env::var("DD_NOISE_KEY_DIR")
            .ok()
            .filter(|s| !s.is_empty())
        {
            cp_noise_pubkey = crate::noise_m2m::load_cp_pubkey(std::path::Path::new(&dir));
        }
    }

    spawn_cloudflared(b.tunnel_token);

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

    let gh = gh_oidc::Verifier::new(cfg.common.owner.clone(), "dd-agent".into());

    let state = St {
        cfg: cfg.clone(),
        ee,
        hostname: b.hostname,
        agent_id: b.agent_id,
        started: Instant::now(),
        ita_token,
        extras: Arc::new(RwLock::new(cfg.extra_ingress.clone())),
        gh,
        noise_key,
        cp_noise_pubkey,
    };

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/workload/{id}", get(workload_page))
        .route("/deploy", post(deploy))
        .route("/exec", post(exec))
        .route("/logs/{app}", get(logs))
        .route("/api/agents", get(api_agents_proxy))
        .fallback(log_unmatched)
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cfg.common.port);
    eprintln!("agent: listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .map_err(|e| Error::Internal(e.to_string()))
}

#[derive(Debug, serde::Deserialize)]
struct Bootstrap {
    tunnel_token: String,
    hostname: String,
    agent_id: String,
    #[allow(dead_code)]
    cp_hostname: String,
    /// CP's long-term Noise static pubkey (hex), advertised so the
    /// agent can pin it for future m2m handshakes. Absent in
    /// migration-window deployments where the CP hasn't been given
    /// a key dir yet.
    #[serde(default)]
    cp_noise_pubkey_hex: Option<String>,
}

async fn register(cfg: &Cfg, ita_token: &str, noise_pubkey_hex: Option<&str>) -> Result<Bootstrap> {
    let http = reqwest::Client::new();
    let url = format!("{}/register", cfg.cp_url.trim_end_matches('/'));
    let extra_ingress: Vec<serde_json::Value> = cfg
        .extra_ingress
        .iter()
        .map(|(label, port)| serde_json::json!({"hostname_label": label, "port": port}))
        .collect();
    let body = serde_json::json!({
        "vm_name": cfg.common.vm_name,
        "env_label": cfg.common.env_label,
        "owner": cfg.common.owner,
        "ita_token": ita_token,
        "extra_ingress": extra_ingress,
        "noise_pubkey_hex": noise_pubkey_hex,
    });
    // /register is CF-Access-bypassed; ITA attestation is the gate.
    let resp = http
        .post(&url)
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

/// 404 with a log line. Without this, a request to a path nobody
/// registered (e.g. caused by a proxy rewrite, or a typo'd CI URL)
/// would silently get axum's default 404 — and on the dd-deploy
/// side, curl doesn't see a body, so the symptom looks like "empty
/// 200". Logging the unmatched method+path gives us ground truth
/// for whether a request reached dd-agent at all.
async fn log_unmatched(
    method: axum::http::Method,
    uri: axum::http::Uri,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    eprintln!("agent: 404 {} {}", method, uri.path());
    (
        axum::http::StatusCode::NOT_FOUND,
        Json(serde_json::json!({"code":"NOT_FOUND","message":"unmatched route"})),
    )
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
    let extra_ingress: Vec<serde_json::Value> = s
        .extras
        .read()
        .await
        .iter()
        .map(|(label, port)| serde_json::json!({"hostname_label": label, "port": port}))
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "service": "agent",
        "agent_id": s.agent_id,
        "vm_name": s.cfg.common.vm_name,
        "hostname": s.hostname,
        "owner": s.cfg.common.owner,
        "attestation_type": ee_health["attestation_type"].as_str().unwrap_or("unknown"),
        "deployments": deployments,
        "deployment_count": list["deployments"].as_array().map(|a| a.len()).unwrap_or(0),
        "cpu_percent": m.cpu_pct,
        "memory_used_mb": m.mem_used_mb,
        "memory_total_mb": m.mem_total_mb,
        "swap_used_mb": m.swap_used_mb,
        "swap_total_mb": m.swap_total_mb,
        "load_1m": m.load_1m,
        "load_5m": m.load_5m,
        "load_15m": m.load_15m,
        "nets": m.nets,
        "disks": m.disks,
        "uptime_secs": s.started.elapsed().as_secs(),
        "system_uptime_secs": m.uptime_secs,
        "ita_token": ita_token,
        "extra_ingress": extra_ingress,
    }))
}

async fn dashboard(State(s): State<St>) -> Response {
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
        rows.push_str(&format!(
            r#"<tr><td><a href="/workload/{id}">{app}</a></td><td><span class="pill {cls}">{status}</span></td><td class="dim">{image}</td><td><a href="/workload/{id}">logs</a></td></tr>"#
        ));
    }

    let table = if deployments.is_empty() {
        r#"<div class="empty">No workloads running</div>"#.to_string()
    } else {
        format!(
            r#"<table><tr><th>app</th><th>status</th><th>image</th><th></th></tr>{rows}</table>"#
        )
    };

    // `{hostname-base}-block.{tld}` is the bastion subdomain provisioned
    // at register time. Human-gated by CF Access; the block-aware
    // terminal UI (persistent per-session, OSC 133 command history)
    // lives there. Flat shape so Universal SSL covers the cert.
    let term_host = html::escape(&crate::cf::label_hostname(&s.hostname, "block"));

    let body = format!(
        r#"<h1>{hostname}</h1>
<div class="sub">{vm} · {att}</div>
<div class="meta"><span class="ok">healthy</span> · uptime {up} · {count} workload(s) · <a href="https://{term_host}/" target="_blank">Terminal ↗</a></div>
<div class="cards">
  <div class="card"><div class="label">CPU</div><div class="value green">{cpu}%</div></div>
  <div class="card"><div class="label">Memory</div><div class="value blue">{mu} / {mt}</div></div>
  <div class="card"><div class="label">Load 1m</div><div class="value mauve">{load:.2}</div></div>
</div>
<div class="section">Workloads</div>{table}"#,
        term_host = term_host,
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

async fn workload_page(State(s): State<St>, Path(id): Path<String>) -> Result<Response> {
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

/// Extract + verify a GitHub Actions OIDC bearer token. The /deploy
/// and /exec endpoints are CF-Access-bypassed; this is the real gate.
async fn require_gh_oidc(s: &St, headers: &HeaderMap) -> Result<gh_oidc::Claims> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Unauthorized)?;
    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or(Error::Unauthorized)?;
    s.gh.verify(token).await
}

async fn deploy(
    State(s): State<St>,
    headers: HeaderMap,
    Json(spec): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    // Log entry *before* auth so we can tell CF-Access-intercepts
    // (no handler entry at all) from OIDC failures (entry + reject).
    eprintln!(
        "agent: /deploy entered (has_auth={}, app={})",
        headers.contains_key(axum::http::header::AUTHORIZATION),
        spec.get("app_name").and_then(|v| v.as_str()).unwrap_or("?")
    );
    let claims = require_gh_oidc(&s, &headers).await?;
    eprintln!(
        "agent: /deploy by {} (repo={}, ref={})",
        claims.sub, claims.repository, claims.ref_
    );

    // Pull `expose` off the spec before forwarding to EE. EE ignores
    // unknown fields today but keeping the payload tidy avoids future
    // surprises if EE ever grows stricter parsing.
    let expose = parse_expose(&spec);

    let response = s.ee.deploy(spec).await?;

    if let Some((label, port)) = expose {
        if let Err(e) = push_extra_ingress(&s, label.clone(), port).await {
            // Soft-fail: the workload is deployed, the owner just can't
            // reach it from the public internet yet. Better than failing
            // the whole /deploy and leaving the caller unsure whether
            // the process is running.
            eprintln!(
                "agent: /ingress/replace add {label}:{port} failed (workload still running): {e}"
            );
        }
    }

    Ok(Json(response))
}

/// Extract `expose.hostname_label` + `expose.port` from a DeployRequest
/// JSON body. Returns None if the field is missing or malformed; the
/// caller treats that as "no runtime ingress requested" and moves on.
fn parse_expose(spec: &serde_json::Value) -> Option<(String, u16)> {
    let expose = spec.get("expose")?;
    let label = expose.get("hostname_label")?.as_str()?.to_string();
    let port = expose.get("port")?.as_u64()?;
    if label.is_empty() || port == 0 || port > u16::MAX as u64 {
        return None;
    }
    Some((label, port as u16))
}

/// Append `(label, port)` to the live extras list (dedup by label —
/// redeploying the same app_name with the same hostname_label is a
/// no-op, not a duplicate rule) and POST the full list to the CP's
/// /ingress/replace endpoint. The CP re-PUTs the tunnel config and
/// upserts CNAMEs.
async fn push_extra_ingress(s: &St, label: String, port: u16) -> Result<()> {
    let extras = {
        let mut guard = s.extras.write().await;
        if let Some(existing) = guard.iter_mut().find(|(l, _)| *l == label) {
            existing.1 = port;
        } else {
            guard.push((label, port));
        }
        guard.clone()
    };

    let body_extras: Vec<serde_json::Value> = extras
        .iter()
        .map(|(l, p)| serde_json::json!({"hostname_label": l, "port": p}))
        .collect();

    // Prefer Noise RPC when both sides have pinned keys — closes out
    // the ITA-bearer-on-every-call pattern. The HTTP+ITA path below
    // stays live as a migration fallback for any agent/CP pair
    // where one side doesn't have a key yet.
    if let (Some(key), Some(pk)) = (s.noise_key.as_ref(), s.cp_noise_pubkey.as_ref()) {
        let wss = http_to_wss(&s.cfg.cp_url) + "/noise/rpc";
        let req = serde_json::json!({
            "op": "ingress_replace",
            "agent_id": s.agent_id,
            "extras": body_extras.clone(),
        });
        match crate::noise_rpc::call(&wss, key, pk, req).await {
            Ok(resp) if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) => {
                eprintln!(
                    "agent: ingress/replace (noise) ok ({} extras total)",
                    extras.len()
                );
                return Ok(());
            }
            Ok(resp) => {
                let msg = resp
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                eprintln!("agent: ingress/replace (noise) rejected: {msg} — falling back to HTTP");
            }
            Err(e) => {
                eprintln!("agent: ingress/replace (noise) error: {e} — falling back to HTTP");
            }
        }
    }

    let ita_token = s.ita_token.read().await.clone();
    let body = serde_json::json!({
        "agent_id": s.agent_id,
        "ita_token": ita_token,
        "extras": body_extras,
    });

    let url = format!("{}/ingress/replace", s.cfg.cp_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| Error::Upstream(format!("ingress/replace {url}: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(Error::Upstream(format!(
            "ingress/replace {url} → {status}: {text}"
        )));
    }
    eprintln!(
        "agent: ingress/replace (http) ok ({} extras total)",
        extras.len()
    );
    Ok(())
}

/// Convert an http(s) URL to a ws(s) URL for WebSocket upgrade. Keeps
/// the host/port/path intact; only the scheme changes.
fn http_to_wss(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{}", rest.trim_end_matches('/'))
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{}", rest.trim_end_matches('/'))
    } else {
        url.trim_end_matches('/').to_string()
    }
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

/// GET /logs/{app} — look up the EE deployment id for `app` and
/// return EE's captured stdout. Gated by GH OIDC, same as /deploy
/// and /exec. 404 if no deployment with that `app_name` exists —
/// not a server error, callers often probe for optional workloads.
async fn logs(
    State(s): State<St>,
    Path(app): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let _ = require_gh_oidc(&s, &headers).await?;
    let list = s.ee.list().await?;
    let id = list["deployments"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|d| d["app_name"].as_str() == Some(app.as_str()))
        })
        .and_then(|d| d["id"].as_str())
        .map(String::from)
        .ok_or(Error::NotFound)?;
    Ok(Json(s.ee.logs(&id).await?))
}

/// GET /api/agents — loopback-only proxy to the CP's same-named
/// endpoint. Uses this agent's own ITA token as the Bearer, so the
/// CP's ITA verifier accepts the call without needing a GH OIDC
/// JWT or service token. Bastion on this VM calls
/// `http://localhost:8080/api/agents` to get the fleet catalog
/// without having to cross-origin to the CP's public hostname.
async fn api_agents_proxy(
    State(s): State<St>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<Json<serde_json::Value>> {
    if !peer.ip().is_loopback() {
        return Err(Error::Unauthorized);
    }
    let token = s.ita_token.read().await.clone();
    let url = format!("{}/api/agents", s.cfg.cp_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&token)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await
        .map_err(|e| Error::Upstream(format!("cp /api/agents: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Upstream(format!(
            "cp /api/agents → {status}: {body}"
        )));
    }
    Ok(Json(resp.json().await?))
}

async fn exec(
    State(s): State<St>,
    headers: HeaderMap,
    Json(req): Json<ExecReq>,
) -> Result<Json<serde_json::Value>> {
    let _ = require_gh_oidc(&s, &headers).await?;
    Ok(Json(s.ee.exec(&req.cmd, req.timeout_secs).await?))
}
