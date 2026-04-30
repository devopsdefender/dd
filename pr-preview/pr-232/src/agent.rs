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
//!   - Terminal is a separate `ttyd` workload published on
//!     `block.<hostname>` — a plain web shell, not tied to any
//!     deployment.
//!   - `/deploy` and `/exec` are CF-Access-bypassed and gated in-code
//!     by a GitHub Actions OIDC token — any CI workflow whose
//!     principal matches `DD_OWNER`/`DD_OWNER_ID`/`DD_OWNER_KIND`
//!     (see [`gh_oidc::Principal::matches`]) can call them by
//!     presenting its per-job OIDC JWT as `Authorization: Bearer …`.
//!   - Agent → CP `/ingress/replace` calls include the agent's fresh
//!     ITA token in the body; the CP verifies it against Intel.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::config::Agent as Cfg;
use crate::ee::Ee;
use crate::error::{Error, Result};
use crate::gh_oidc;
use crate::html::{self, shell};
use crate::ita;
use crate::metrics;
use crate::noise_gateway;
use crate::taint::{TaintReason, TaintSet};

/// Re-mint interval. Intel ITA tokens typically expire in a few
/// minutes; refresh well before so `/health` always serves a live
/// token to the CP's collector.
const ITA_REFRESH: Duration = Duration::from_secs(180);

/// Poll interval for syncing the device trust list from the CP.
/// Tuned so a revoke propagates within ~30s.
const DEVICES_POLL: Duration = Duration::from_secs(30);

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
    /// and /exec. CI workflows whose principal matches
    /// `DD_OWNER`/`DD_OWNER_ID`/`DD_OWNER_KIND` can call them
    /// without any shared secret; anyone else is denied at claim
    /// check.
    gh: Arc<gh_oidc::Verifier>,
    /// Runtime tenant-owner set via `POST /owner`. When `Some(p)`,
    /// `/deploy` / `/exec` / `/logs` accept GitHub OIDC from EITHER
    /// the fleet principal OR `p` — shared admin. The `/owner`
    /// endpoint itself is gated on fleet-only auth. Reset to `None`
    /// on every agent boot (no persistence); the s12e bot reapplies
    /// via `/owner` if the claim is still active after a restart.
    agent_owner: Arc<RwLock<Option<gh_oidc::Principal>>>,
    /// TDX-quote + Noise-static-pubkey bundle. Served as
    /// `{ noise: { quote_b64, pubkey_hex } }` off `/health` so a
    /// bastion-app can bootstrap a Noise session in one fetch (used
    /// to be a separate `/attest` endpoint — folded in here). Shared
    /// `Arc` with the Noise gateway module's handshake responder;
    /// one keypair / one quote per boot.
    attest: Arc<noise_gateway::attest::Attestor>,
    /// Integrity taint-reason set. Seeded at boot (ArbitraryExecEnabled
    /// when mutation routes are registered) and appended at runtime
    /// as events happen (`/owner` → CustomerOwnerEnabled, `/deploy`
    /// ok → CustomerWorkloadDeployed). Mirrored in `/health`.
    taint: TaintSet,
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

    // Noise gateway runs in-process too: this agent serves the
    // pre-handshake bundle inline on /health (`.noise.quote_b64` +
    // `.noise.pubkey_hex`) and the Noise_IK responder on /noise/ws,
    // both on the same port 8080 as everything else, so bastion-app
    // CLIs can attach directly to the agent's EE instance without
    // going through the CP.
    let trust = noise_gateway::new_trust_handle();

    // Background poll for the device trust list. Mutates `trust`
    // in place so the local Noise responder picks up revocations
    // within ~DEVICES_POLL.
    {
        let cp_url = cfg.cp_url.clone();
        let token = ita_token.clone();
        let trust = trust.clone();
        tokio::spawn(async move {
            let http = reqwest::Client::new();
            loop {
                if let Err(e) = sync_trusted_devices(&http, &cp_url, &token, &trust).await {
                    eprintln!("agent: device sync failed: {e}");
                }
                tokio::time::sleep(DEVICES_POLL).await;
            }
        });
    }

    // Attestation keypair + upstream EE client for the Noise gateway.
    let noise_key_path: std::path::PathBuf = std::env::var("DD_NOISE_KEY_PATH")
        .unwrap_or_else(|_| "/run/devopsdefender/noise.key".into())
        .into();
    let attestor = Arc::new(
        noise_gateway::attest::Attestor::load_or_mint(&noise_key_path)
            .await
            .map_err(|e| Error::Internal(format!("noise keypair: {e}")))?,
    );
    eprintln!("agent: noise_pubkey={}", hex::encode(attestor.public_key()));
    let ee_token = std::env::var("EE_TOKEN").ok();
    let upstream = Arc::new(noise_gateway::upstream::EeAgent::new(
        std::path::PathBuf::from(noise_gateway::upstream::DEFAULT_EE_AGENT_SOCK),
        ee_token,
    ));
    let ng_state = noise_gateway::State {
        attest: attestor.clone(),
        trust,
        upstream,
    };

    let gh = gh_oidc::Verifier::new(cfg.common.owner.clone(), "dd-agent".into());

    // Seed taint set. Boot-time facts go in now; runtime events
    // (CustomerOwnerEnabled, CustomerWorkloadDeployed) are appended
    // by their respective handlers as they happen.
    let mut boot_taint: Vec<TaintReason> = Vec::new();
    if !cfg.confidential {
        boot_taint.push(TaintReason::ArbitraryExecEnabled);
    }
    let taint = TaintSet::with_initial(boot_taint);

    let state = St {
        cfg: cfg.clone(),
        ee,
        hostname: b.hostname,
        agent_id: b.agent_id,
        started: Instant::now(),
        ita_token,
        extras: Arc::new(RwLock::new(cfg.extra_ingress.clone())),
        gh,
        attest: attestor,
        agent_owner: Arc::new(RwLock::new(None)),
        taint,
    };

    // Confidential mode: `/deploy`, `/exec`, and `/owner` are not
    // registered at all — they 404 rather than 401. Attestation +
    // the taint-reason set (see /health) prove to third parties
    // that these mutation channels are absent, without requiring
    // trust in the agent's HTTP response ("disabled? really?").
    // `/logs` stays available so observers can still stream output
    // from the sealed workload.
    let mut app = Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/workload/{id}", get(workload_page))
        .route("/logs/{app}", get(logs));
    if !cfg.confidential {
        app = app
            .route("/deploy", post(deploy))
            .route("/exec", post(exec))
            .route("/owner", post(set_owner));
    }
    let app = app
        .fallback(log_unmatched)
        .with_state(state)
        .merge(noise_gateway::router(ng_state))
        // Wire-level request log. Fires for every HTTP request the
        // listener accepts — strictly before any extractor runs and
        // strictly after any handler returns, so it draws a line
        // between "request reached axum" and "request died in
        // CF/cloudflared before us" (the `/deploy` 2xx-empty-body
        // bug from GH Actions runners). One line in, one line out,
        // per request — cheap enough to keep on in prod.
        .layer(axum::middleware::from_fn(log_http));

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

/// Logs one line per inbound HTTP request before any extractor runs,
/// and one line for the final response status. Primary motivation:
/// the `/deploy` handler's "entered" eprintln never fires for the
/// empty-2xx failures from GH runners, leaving ambiguous whether
/// the request ever crossed the CF+cloudflared boundary. This pins
/// down that boundary.
///
/// Headers logged (presence or value) — chosen because each one
/// distinguishes a plausible failure mode:
///   - Content-Type + Content-Length: whether the body extractor
///     (`Json`) would accept/reject on arrival.
///   - Authorization (presence only, never the token): auth vs.
///     no-auth path.
///   - User-Agent: GH runners' curl leaves a distinct UA; a rewrite
///     upstream would show here.
///   - CF-Ray + CF-Connecting-IP: cross-reference with CF edge logs
///     — ground truth for "did CF see this and from where?"
async fn log_http(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let h = req.headers();
    let get = |k: &str| {
        h.get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string()
    };
    let auth = if h.contains_key(axum::http::header::AUTHORIZATION) {
        "yes"
    } else {
        "no"
    };
    eprintln!(
        "agent: IN {method} {path} auth={auth} ct={} cl={} ua={} cf-ray={} cf-ip={}",
        get("content-type"),
        get("content-length"),
        get("user-agent"),
        get("cf-ray"),
        get("cf-connecting-ip"),
    );
    let res = next.run(req).await;
    eprintln!("agent: OUT {method} {path} -> {}", res.status().as_u16());
    res
}

/// Pull the CP's device registry (`{"pubkeys": ["<hex>", ...]}`) and
/// atomically replace the local `TrustHandle`. The local Noise
/// responder reads this set directly; revocations propagate within
/// one `DEVICES_POLL` tick.
async fn sync_trusted_devices(
    http: &reqwest::Client,
    cp_url: &str,
    ita_token: &Arc<RwLock<String>>,
    trust: &noise_gateway::TrustHandle,
) -> Result<()> {
    // `/api/v1/devices/trusted` is CF-Access-bypassed (see
    // `cf::provision_cp_access`) so cross-VM agents can reach it over
    // the public tunnel. Auth is in-code: loopback / GH-OIDC / ITA,
    // same three-way policy as `/api/agents`.
    let url = format!("{}/api/v1/devices/trusted", cp_url.trim_end_matches('/'));
    let token = ita_token.read().await.clone();
    let resp = http
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| Error::Upstream(format!("devices GET {url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::Upstream(format!(
            "devices GET {url} → {}",
            resp.status()
        )));
    }
    let body: serde_json::Value = resp.json().await?;
    let mut fresh: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    if let Some(arr) = body["pubkeys"].as_array() {
        for v in arr {
            let Some(s) = v.as_str() else { continue };
            let Ok(bytes) = hex::decode(s) else { continue };
            if bytes.len() != 32 {
                continue;
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            fresh.insert(k);
        }
    }
    *trust.write().await = fresh;
    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct Bootstrap {
    tunnel_token: String,
    hostname: String,
    agent_id: String,
}

async fn register(cfg: &Cfg, ita_token: &str) -> Result<Bootstrap> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let url = format!("{}/register", cfg.cp_url.trim_end_matches('/'));
    let extra_ingress: Vec<serde_json::Value> = cfg
        .extra_ingress
        .iter()
        .map(|(label, port)| serde_json::json!({"hostname_label": label, "port": port}))
        .collect();
    let body = serde_json::json!({
        "vm_name": cfg.common.vm_name,
        "ita_token": ita_token,
        "extra_ingress": extra_ingress,
    });

    // /register is CF-Access-bypassed; ITA attestation is the gate.
    // The transport layer is retried — the agent VM often boots
    // faster than CF edge propagation for a just-flipped CP CNAME
    // or a just-reconnected cloudflared tunnel, and the first POST
    // tends to fail with "error sending request" / 502 / 530.
    // Exponential-ish backoff, ~90s total.
    let mut last_err: Option<Error> = None;
    for attempt in 1..=6u32 {
        match http.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                return Ok(resp.json().await?);
            }
            Ok(resp) => {
                let s = resp.status();
                // 4xx from the CP is almost always a real config
                // error (ITA invalid, etc.) — no point retrying.
                if s.is_client_error() && s != reqwest::StatusCode::TOO_MANY_REQUESTS {
                    let b = resp.text().await.unwrap_or_default();
                    return Err(Error::Upstream(format!("register {url} → {s}: {b}")));
                }
                let b = resp.text().await.unwrap_or_default();
                last_err = Some(Error::Upstream(format!("register {url} → {s}: {b}")));
            }
            Err(e) => {
                // Print `{:?}` so the reqwest error chain (TLS,
                // DNS, connect details) lands in the agent log
                // instead of just the wrapper message.
                last_err = Some(Error::Upstream(format!("register {url}: {e:?}")));
            }
        }
        eprintln!(
            "agent: register attempt {attempt}/6 failed ({}) — backing off",
            last_err.as_ref().map(|e| e.to_string()).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_secs(5 * attempt as u64)).await;
    }
    Err(last_err.unwrap_or_else(|| Error::Upstream("register: exhausted retries".into())))
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
    let agent_owner = s.agent_owner.read().await.clone();
    let taint_reasons = s.taint.snapshot().await;
    let extra_ingress: Vec<serde_json::Value> = s
        .extras
        .read()
        .await
        .iter()
        .map(|(label, port)| serde_json::json!({"hostname_label": label, "port": port}))
        .collect();

    // Back-compat surface: pre-Principal /health consumers
    // (satsforcompute's bot, owner-update.yml, anything else keying
    // off the /health JSON) read `agent_owner` and `owner` as plain
    // strings. Keep them strings (the principal `name`) and expose
    // the structured form alongside as `*_principal` for new callers.
    let fleet_owner_name = s.cfg.common.owner.name.clone();
    let agent_owner_name = agent_owner.as_ref().map(|p| p.name.clone());

    Json(serde_json::json!({
        "ok": true,
        "service": "agent",
        "agent_id": s.agent_id,
        "vm_name": s.cfg.common.vm_name,
        "hostname": s.hostname,
        // `owner` / `agent_owner`: strings, principal name only —
        // back-compat for pre-Principal consumers. Structured form
        // (with id and kind) is on the `*_principal` keys below.
        "owner": fleet_owner_name,
        "fleet_owner": fleet_owner_name,
        "agent_owner": agent_owner_name,
        "fleet_owner_principal": s.cfg.common.owner,
        "agent_owner_principal": agent_owner,
        // Integrity surface (SATS_FOR_COMPUTE_SPEC Integrity States).
        // `confidential_mode`: boot-time flag; true → /deploy + /exec
        // + /owner were NOT registered on this agent. Set from
        // `DD_CONFIDENTIAL`.
        // `taint_reasons`: current set, sorted for diff-friendliness.
        // Empty set = pristine. v0: informational — DD doesn't block
        // actions based on the set.
        "confidential_mode": s.cfg.confidential,
        "taint_reasons": taint_reasons,
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
        // Pre-Noise-handshake bundle — stable per boot. Used to be a
        // standalone `GET /attest` endpoint. Keeping it here lets a
        // bastion-app bootstrap with one fetch and drops a CF Access
        // bypass-app per env × per service. `quote_b64` binds the
        // raw Noise pubkey into its TDX `report_data`; clients verify
        // the Intel signature and pin the pubkey from the quote — no
        // TOFU needed.
        "noise": {
            "quote_b64": base64::engine::general_purpose::STANDARD.encode(s.attest.quote()),
            "pubkey_hex": hex::encode(s.attest.public_key()),
        },
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

    // `{hostname-base}-block.{tld}` is the ttyd subdomain provisioned
    // at register time. Human-gated by CF Access. Flat shape so
    // Universal SSL covers the cert.
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

/// Extract the `Authorization: Bearer <jwt>` header and return the
/// trimmed token body. Shared by fleet-only and fleet-or-agent auth
/// paths so the Bearer-parsing shape stays consistent.
fn bearer_token(headers: &HeaderMap) -> Result<&str> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Unauthorized)?;
    auth.strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or(Error::Unauthorized)
}

/// Workload-control auth (`/deploy`, `/exec`, `/logs`): accept a
/// GitHub Actions OIDC token whose principal (per
/// [`gh_oidc::Principal::matches`]) is EITHER the fleet owner
/// (`DD_OWNER`/`DD_OWNER_ID`/`DD_OWNER_KIND`) OR the agent's runtime
/// `agent_owner`. Shared admin — ops and the active tenant both
/// have deploy/exec/logs authority.
async fn require_gh_oidc(s: &St, headers: &HeaderMap) -> Result<gh_oidc::Claims> {
    let token = bearer_token(headers)?;
    let agent_owner = s.agent_owner.read().await.clone();
    s.gh.verify_allowing(token, agent_owner.as_ref()).await
}

/// Fleet-only auth. Used by `/owner`, which re-assigns the tenant:
/// only ops (the fleet principal) may call it, never the tenant
/// themselves.
async fn require_fleet_oidc(s: &St, headers: &HeaderMap) -> Result<gh_oidc::Claims> {
    let token = bearer_token(headers)?;
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

    // Once a runtime deploy has succeeded, the node is not pristine
    // anymore. Set idempotently — only the first successful /deploy
    // per boot actually inserts.
    s.taint.insert(TaintReason::CustomerWorkloadDeployed).await;

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
    eprintln!("agent: ingress/replace ok ({} extras total)", extras.len());
    Ok(())
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

async fn exec(
    State(s): State<St>,
    headers: HeaderMap,
    Json(req): Json<ExecReq>,
) -> Result<Json<serde_json::Value>> {
    let _ = require_gh_oidc(&s, &headers).await?;
    Ok(Json(s.ee.exec(&req.cmd, req.timeout_secs).await?))
}

#[derive(Debug, Deserialize)]
struct OwnerReq {
    /// New tenant principal name. Empty string clears the runtime
    /// owner — after which `/deploy`/`/exec`/`/logs` accept only
    /// the fleet owner again. When non-empty, `agent_owner_id` and
    /// `agent_owner_kind` are required and validated for shape
    /// consistency (see [`gh_oidc::Principal::from_parts`]).
    agent_owner: String,
    /// Numeric GitHub id of the principal. Required when
    /// `agent_owner` is non-empty; ignored when clearing.
    #[serde(default)]
    agent_owner_id: u64,
    /// `"user" | "org" | "repo"`. Required when `agent_owner` is
    /// non-empty.
    #[serde(default)]
    agent_owner_kind: String,
    /// Opaque ID from the caller's claim system (e.g. the s12e bot's
    /// claim issue). Logged for audit; the agent doesn't interpret it.
    #[serde(default)]
    claim_id: String,
}

/// POST /owner — set (or clear) the agent's runtime tenant owner.
/// Fleet-gated: only the fleet principal can reassign a node.
/// Runtime-only state: resets to `None` on reboot, so a crash/restart
/// is self-healing (the bot re-applies if the claim is still active).
async fn set_owner(
    State(s): State<St>,
    headers: HeaderMap,
    Json(req): Json<OwnerReq>,
) -> Result<Json<serde_json::Value>> {
    let claims = require_fleet_oidc(&s, &headers).await?;
    let new_owner: Option<gh_oidc::Principal> = {
        let trimmed = req.agent_owner.trim();
        if trimmed.is_empty() {
            None
        } else {
            let kind = gh_oidc::PrincipalKind::parse(&req.agent_owner_kind)?;
            Some(gh_oidc::Principal::from_parts(
                trimmed.to_string(),
                req.agent_owner_id,
                kind,
            )?)
        }
    };
    let previous = {
        let mut guard = s.agent_owner.write().await;
        let prev = guard.clone();
        guard.clone_from(&new_owner);
        prev
    };
    // Taint only when transitioning to a NON-fleet owner. Clearing
    // (new_owner == None) leaves the existing flag set — we don't
    // untaint a node that was ever customer-owned, since a past
    // tenant could have exfiltrated via /exec while their window
    // was active. Setting to a new tenant is idempotent via HashSet.
    if new_owner.is_some() {
        s.taint.insert(TaintReason::CustomerOwnerEnabled).await;
    }
    let display = |o: &Option<gh_oidc::Principal>| -> String {
        o.as_ref()
            .map(|p| format!("{}({}/{})", p.name, p.kind.as_str(), p.id))
            .unwrap_or_else(|| "<none>".into())
    };
    eprintln!(
        "agent: /owner {} -> {} (by sub={}, claim_id={})",
        display(&previous),
        display(&new_owner),
        claims.sub,
        if req.claim_id.is_empty() {
            "<none>"
        } else {
            req.claim_id.as_str()
        },
    );
    // Same back-compat as /health: existing callers (s12e bot,
    // owner-update.yml) parse `agent_owner` / `previous_owner` as
    // strings. Keep them strings here too; surface the structured
    // form on `*_principal`.
    Ok(Json(serde_json::json!({
        "agent_id": s.agent_id,
        "agent_owner": new_owner.as_ref().map(|p| p.name.clone()),
        "agent_owner_principal": new_owner,
        "previous_owner": previous.as_ref().map(|p| p.name.clone()),
        "previous_owner_principal": previous,
        "claim_id": req.claim_id,
    })))
}
