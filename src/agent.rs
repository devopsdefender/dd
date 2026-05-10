//! Agent mode — runs inside an easyenclave TDX VM.
//!
//! On startup: POST `{vm_name, env_label, owner, ita_token}` to
//! `$DD_CP_URL/register` (ITA attestation is the gate). The CP
//! responds with `{tunnel_token, hostname, agent_id, cp_hostname}`.
//!
//! Auth after registration:
//!   - Browser routes (`/`, `/workload/*`) require a DD-signed
//!     GitHub App session cookie. Cloudflare only routes traffic.
//!   - Terminal access is provided by direct paired-device Noise sessions
//!     to this agent, with browser shell HTTP routes kept as transitional
//!     compatibility.
//!   - `/deploy` and `/exec` are gated in-code by a GitHub Actions
//!     OIDC token — any CI workflow whose
//!     principal matches `DD_OWNER`/`DD_OWNER_ID`/`DD_OWNER_KIND`
//!     (see [`gh_oidc::Principal::matches`]) can call them by
//!     presenting its per-job OIDC JWT as `Authorization: Bearer …`.
//!   - Agent → CP `/ingress/replace` calls include the agent's fresh
//!     ITA token in the body; the CP verifies it against Intel.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::config::Agent as Cfg;
use crate::config::ItaMode;
use crate::ee::Ee;
use crate::error::{Error, Result};
use crate::gh_oidc;
use crate::html::{self, shell};
use crate::ita;
use crate::metrics;
use crate::noise_gateway;
use crate::oracle;
use crate::taint::{IntegrityState, TaintReason, TaintSet};
use crate::units::{self, AgentMode, ManagedUnit, UnitKind};

/// Re-mint interval. Intel ITA tokens typically expire in a few
/// minutes; refresh well before so `/health` always serves a live
/// token to the CP's collector.
const ITA_REFRESH: Duration = Duration::from_secs(180);

const EE_READY_TIMEOUT: Duration = Duration::from_secs(90);

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
    /// Read-only oracle scrape state derived from boot workload metadata.
    oracles: oracle::OracleStore,
    /// Local session supervisor control endpoint. Public callers reach this
    /// through dd-agent; dd-sessiond itself stays loopback-local.
    sessiond_http_url: String,
    /// Local raw attach socket used to proxy PTY bytes over WebSocket.
    sessiond_attach_addr: String,
    http: reqwest::Client,
    /// Agent-local paired-device store. This is the trust source enforced by
    /// the local Noise gateway.
    devices: Arc<crate::devices::Store>,
}

pub async fn run() -> Result<()> {
    let cfg = Arc::new(Cfg::from_env()?);
    let ee = Arc::new(Ee::new(&cfg.ee_socket));

    let h = ee.wait_ready(EE_READY_TIMEOUT).await?;
    eprintln!(
        "agent: EE connected (attestation={})",
        h["attestation_type"].as_str().unwrap_or("?")
    );
    eprintln!("agent: ITA mode={:?}", cfg.ita.mode);

    eprintln!("agent: registering with {}", cfg.cp_url);
    let (initial_token, b) = register(&cfg, &ee).await?;
    eprintln!("agent: registered as {}", b.hostname);

    spawn_cloudflared(b.tunnel_token);
    let oracle_store = oracle::initial_store(&cfg.oracles, &b.hostname);
    oracle::spawn_scrapers(cfg.oracles.clone(), oracle_store.clone());

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
    let devices = crate::devices::Store::load(cfg.devices_path.clone(), trust.clone())
        .await
        .map_err(|e| Error::Internal(format!("agent devices store load: {e}")))?;

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
    let sessiond_http_url =
        std::env::var("DD_SESSIOND_HTTP_URL").unwrap_or_else(|_| "http://127.0.0.1:7683".into());
    let sessiond_attach_addr =
        std::env::var("DD_SESSIOND_ATTACH_ADDR").unwrap_or_else(|_| "127.0.0.1:7684".into());
    let shell = Arc::new(noise_gateway::upstream::Sessiond::new(
        sessiond_http_url.clone(),
        sessiond_attach_addr.clone(),
    ));
    let ng_state = noise_gateway::State {
        attest: attestor.clone(),
        trust,
        upstream,
        shell: Some(shell),
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
        oracles: oracle_store,
        sessiond_http_url,
        sessiond_attach_addr,
        http: crate::system_http_client(),
        devices,
    };
    let api_state = state.clone();
    let api_ng_state = ng_state.clone();

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
        .route("/api/oracles", get(api_oracles))
        .route("/api/units", get(api_units))
        .route("/api/sessions", get(api_sessions).post(create_session))
        .route("/api/sessions/{id}/replay", get(replay_session))
        .route("/api/sessions/{id}/resize", post(resize_session))
        .route("/api/sessions/{id}/close", post(close_session))
        .route("/api/sessions/{id}/attach", get(attach_session))
        .route("/api/v1/devices", post(create_device))
        .route("/api/v1/devices/{pubkey}", delete(revoke_device))
        .route("/admin/enroll", get(enroll_page))
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

    let mut api = Router::new()
        .route("/health", get(health))
        .route("/api/oracles", get(api_oracles))
        .route("/api/units", get(api_units))
        .route("/api/sessions", get(api_sessions).post(create_session))
        .route("/api/sessions/{id}/replay", get(replay_session))
        .route("/api/sessions/{id}/resize", post(resize_session))
        .route("/api/sessions/{id}/close", post(close_session))
        .route("/api/sessions/{id}/attach", get(attach_session))
        .route("/logs/{app}", get(logs));
    if !cfg.confidential {
        api = api
            .route("/deploy", post(deploy))
            .route("/exec", post(exec))
            .route("/owner", post(set_owner));
    }
    let api = api
        .fallback(log_unmatched)
        .with_state(api_state)
        .merge(noise_gateway::router(api_ng_state))
        .layer(axum::middleware::from_fn(log_http));
    let api_addr = format!("0.0.0.0:{}", crate::cf::AGENT_API_PORT);
    eprintln!("agent: api listening on {api_addr}");
    let api_listener = tokio::net::TcpListener::bind(&api_addr).await?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            api_listener,
            api.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        {
            eprintln!("agent: api listener exited: {e}");
        }
    });

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

#[derive(Debug, serde::Deserialize)]
struct Bootstrap {
    tunnel_token: String,
    hostname: String,
    agent_id: String,
}

enum RegisterAttempt {
    Retry(Error),
    Fatal(Error),
}

async fn register(cfg: &Cfg, ee: &Ee) -> Result<(String, Bootstrap)> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .no_hickory_dns()
        .build()
        .unwrap_or_else(|_| crate::system_http_client());
    let url = format!("{}/register", cfg.cp_url.trim_end_matches('/'));
    let extra_ingress: Vec<serde_json::Value> = cfg
        .extra_ingress
        .iter()
        .map(|(label, port)| serde_json::json!({"hostname_label": label, "port": port}))
        .collect();

    // /register is authenticated by a fresh ITA attestation token. The
    // CP and its Cloudflare route are allowed to disappear during a
    // deploy; a long-lived local dev agent should keep trying instead
    // of becoming permanently dead. Client errors other than rate
    // limiting are still fatal because they usually mean bad config
    // or failed attestation.
    let mut attempt = 1u64;
    loop {
        let ita_token = match mint_ita(cfg, ee).await {
            Ok(token) => {
                eprintln!("agent: ITA token minted for register attempt {attempt}");
                token
            }
            Err(e) => {
                let delay = register_backoff(attempt);
                eprintln!(
                    "agent: register attempt {attempt} could not mint ITA token ({e}) — backing off {}s",
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
                attempt = attempt.saturating_add(1);
                continue;
            }
        };

        match register_once(&http, cfg, &url, &extra_ingress, &ita_token).await {
            Ok(bootstrap) => return Ok((ita_token, bootstrap)),
            Err(RegisterAttempt::Fatal(e)) => return Err(e),
            Err(RegisterAttempt::Retry(e)) => {
                let delay = register_backoff(attempt);
                eprintln!(
                    "agent: register attempt {attempt} failed ({e}) — backing off {}s",
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

async fn register_once(
    http: &reqwest::Client,
    cfg: &Cfg,
    url: &str,
    extra_ingress: &[serde_json::Value],
    ita_token: &str,
) -> std::result::Result<Bootstrap, RegisterAttempt> {
    let body = serde_json::json!({
        "vm_name": cfg.common.vm_name,
        "ita_token": ita_token,
        "extra_ingress": extra_ingress,
    });

    match http.post(url).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => resp
            .json()
            .await
            .map_err(Error::from)
            .map_err(RegisterAttempt::Retry),
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let err = Error::Upstream(format!("register {url} → {status}: {body}"));
            if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
                Err(RegisterAttempt::Fatal(err))
            } else {
                Err(RegisterAttempt::Retry(err))
            }
        }
        Err(e) => {
            // Print `{:?}` so the reqwest error chain (TLS, DNS,
            // connect details) lands in the agent log instead of just
            // the wrapper message.
            Err(RegisterAttempt::Retry(Error::Upstream(format!(
                "register {url}: {e:?}"
            ))))
        }
    }
}

fn register_backoff(attempt: u64) -> Duration {
    Duration::from_secs((attempt.saturating_mul(5)).clamp(5, 60))
}

/// Mint an Intel-signed TDX attestation JWT. Registration retries mint
/// failures because a long-lived local agent may boot while ITA or the
/// CP path is temporarily unavailable.
async fn mint_ita(cfg: &Cfg, ee: &Ee) -> Result<String> {
    if cfg.ita.mode == ItaMode::Local {
        return ita::mint_local(&cfg.ita.issuer, &cfg.ita.api_key, &cfg.common.vm_name);
    }
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
    let oracles = s.oracles.read().await.clone();
    let taint_reasons = s.taint.snapshot().await;
    let integrity_state = IntegrityState::from_taint_reasons(&taint_reasons);
    let agent_mode = AgentMode::from_confidential(s.cfg.confidential);
    let units = managed_units(&s, &list, &oracles, agent_mode, integrity_state).await;
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
        "ita_mode": s.cfg.ita.mode.as_str(),
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
        // `integrity_state`: user-facing label derived from the
        // internal taint set. Empty set = clean; any reason =
        // controlled. v0: informational — DD doesn't block actions
        // based on the set.
        // `integrity_reasons`: current set, sorted for
        // diff-friendliness. `taint_reasons` is kept as a diagnostic
        // compatibility alias for existing consumers.
        "confidential_mode": s.cfg.confidential,
        "agent_mode": agent_mode,
        "integrity_state": integrity_state,
        "integrity_reasons": taint_reasons.clone(),
        "taint_reasons": taint_reasons,
        "attestation_type": ee_health["attestation_type"].as_str().unwrap_or("unknown"),
        "deployments": deployments,
        "deployment_count": list["deployments"].as_array().map(|a| a.len()).unwrap_or(0),
        "oracle_count": oracles.len(),
        "oracles": oracles,
        "unit_count": units.len(),
        "units": units,
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
        // bastion-app bootstrap with one fetch and keeps Cloudflare
        // routing app count lower. `quote_b64` binds the
        // raw Noise pubkey into its TDX `report_data`; clients verify
        // the Intel signature and pin the pubkey from the quote — no
        // TOFU needed.
        "noise": {
            "quote_b64": base64::engine::general_purpose::STANDARD.encode(s.attest.quote()),
            "pubkey_hex": hex::encode(s.attest.public_key()),
        },
    }))
}

fn agent_path_and_query(uri: &Uri) -> &str {
    uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
}

fn require_browser_auth(s: &St, headers: &HeaderMap, uri: &Uri) -> Option<Response> {
    if s.cfg
        .auth
        .verify_session(&s.cfg.common.owner, headers)
        .is_some()
    {
        None
    } else {
        let return_to =
            crate::auth::absolute_url(headers, &s.cfg.common.vm_name, agent_path_and_query(uri));
        Some(crate::auth::unauthorized_or_redirect(
            &s.cfg.auth,
            headers,
            &return_to,
        ))
    }
}

async fn dashboard(State(s): State<St>, headers: HeaderMap, uri: Uri) -> Response {
    if let Some(resp) = require_browser_auth(&s, &headers, &uri) {
        return resp;
    }
    let m = metrics::collect().await;
    let list = s.ee.list().await.unwrap_or_default();
    let ee_health = s.ee.health().await.unwrap_or_default();
    let att = ee_health["attestation_type"].as_str().unwrap_or("unknown");
    let oracles = s.oracles.read().await.clone();
    let taint_reasons = s.taint.snapshot().await;
    let integrity_state = IntegrityState::from_taint_reasons(&taint_reasons);
    let agent_mode = AgentMode::from_confidential(s.cfg.confidential);
    let units = managed_units(&s, &list, &oracles, agent_mode, integrity_state).await;

    let deployments: Vec<&serde_json::Value> = list["deployments"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();

    if agent_mode == AgentMode::ReadOnly && !oracles.is_empty() {
        let primary = &oracles[0];
        let primary_unit = units.iter().find(|u| u.app_name == primary.app_name);
        let public_view = primary
            .vanity_url
            .as_ref()
            .map(|url| {
                format!(
                    r#"<a class="break" href="{url}" target="_blank">{url}</a>"#,
                    url = html::escape(url)
                )
            })
            .unwrap_or_else(|| r#"<span class="dim">not exposed</span>"#.into());
        let sample = primary
            .sample
            .as_ref()
            .and_then(|v| serde_json::to_string_pretty(v).ok())
            .map(|s| html::escape(&s))
            .unwrap_or_else(|| r#"<span class="dim">No successful scrape yet</span>"#.into());
        let logs = primary_unit
            .map(|u| {
                if u.log_line_count == 0 {
                    r#"<span class="dim">No logs yet</span>"#.to_string()
                } else {
                    format!(
                        r#"<a href="/workload/{id}">{n} line(s)</a>"#,
                        id = html::escape(&u.id),
                        n = u.log_line_count
                    )
                }
            })
            .unwrap_or_else(|| r#"<span class="dim">not attached</span>"#.into());
        let recent_logs = match primary_unit {
            Some(u) => recent_log_lines_html(&s.ee, &u.id, 80).await,
            None => r#"<span class="dim">No workload log stream attached</span>"#.into(),
        };

        let mut unit_rows = String::new();
        for u in &units {
            let refs = if u.refs.is_empty() {
                r#"<span class="dim">none</span>"#.to_string()
            } else {
                u.refs
                    .iter()
                    .map(|r| html::unit_ref(&r.label, &r.value))
                    .collect::<Vec<_>>()
                    .join(" · ")
            };
            unit_rows.push_str(&format!(
                r#"<tr><td>{title}<div class="dim">{app}</div></td><td>{kind}</td><td><span class="pill {cls}">{status}</span></td><td>{refs}</td></tr>"#,
                title = html::escape(&u.title),
                app = html::escape(&u.app_name),
                kind = html::escape(u.kind.as_str()),
                cls = status_class(&u.status),
                status = html::escape(&u.status),
                refs = refs,
            ));
        }

        let body = format!(
            r#"<h1>{title}</h1>
<div class="sub">{host} · {vm} · {att}</div>
<div class="meta"><span class="ok">read-only</span> · integrity {integrity} · public oracle view</div>
<div class="cards">
  <div class="card"><div class="label">Oracle status</div><div class="value green">{status}</div></div>
  <div class="card"><div class="label">Public view</div><div class="value small">{public_view}</div></div>
  <div class="card"><div class="label">Last ok</div><div class="value small">{last_ok}</div></div>
  <div class="card"><div class="label">Logs</div><div class="value small">{logs}</div></div>
</div>
<div class="section">Latest public sample</div>
<pre style="max-height:42vh">{sample}</pre>
<div class="section">Recent captured logs</div>
<pre style="max-height:42vh">{recent_logs}</pre>
<div class="section">Managed components</div>
<table><tr><th>component</th><th>kind</th><th>status</th><th>refs</th></tr>{unit_rows}</table>"#,
            title = html::escape(&primary.title),
            host = html::escape(&s.hostname),
            vm = html::escape(&s.cfg.common.vm_name),
            att = html::escape(att),
            integrity = html::escape(integrity_label(integrity_state)),
            status = html::escape(&primary.status),
            public_view = public_view,
            last_ok = html::escape(primary.last_ok.as_deref().unwrap_or("never")),
            logs = logs,
            sample = sample,
            recent_logs = recent_logs,
            unit_rows = unit_rows,
        );

        return Html(shell(
            &format!("DD — {}", primary.title),
            &html::nav(&[("Oracle", "/", true)]),
            &body,
        ))
        .into_response();
    }

    let mut rows = String::new();
    for d in &deployments {
        let status = d["status"].as_str().unwrap_or("idle");
        let cls = status_class(status);
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

    let oracle_section = if oracles.is_empty() {
        String::new()
    } else {
        let mut rows = String::new();
        for o in &oracles {
            let cls = match o.status.as_str() {
                "healthy" => "healthy",
                "error" => "failed",
                _ => "idle",
            };
            let vanity = o
                .vanity_url
                .as_ref()
                .map(|u| {
                    format!(
                        r#"<a href="{url}" target="_blank">{label}</a>"#,
                        url = html::escape(u),
                        label = html::escape(&o.hostname_label)
                    )
                })
                .unwrap_or_else(|| r#"<span class="dim">none</span>"#.into());
            rows.push_str(&format!(
                r#"<tr><td>{title}</td><td><span class="pill {cls}">{status}</span></td><td>{vanity}</td><td class="dim">{path}</td><td class="dim">{last}</td></tr>"#,
                title = html::escape(&o.title),
                status = html::escape(&o.status),
                path = html::escape(&o.path),
                last = html::escape(o.last_ok.as_deref().unwrap_or("never")),
            ));
        }
        format!(
            r#"<div class="section">Read-only oracles</div><table><tr><th>oracle</th><th>status</th><th>vanity</th><th>path</th><th>last ok</th></tr>{rows}</table>"#
        )
    };

    let terminal_link = if units.iter().any(|u| u.kind == UnitKind::Shell) {
        // `{hostname-base}-shell.{tld}` is the dd-shell subdomain provisioned
        // at register time. Human-gated by DD browser auth. Flat shape so
        // Universal SSL covers the cert.
        let term_host = html::escape(&crate::cf::label_hostname(&s.hostname, "shell"));
        format!(r#" · <a href="https://{term_host}/" target="_blank">Terminal ↗</a>"#)
    } else {
        String::new()
    };

    let body = format!(
        r#"<h1>{hostname}</h1>
<div class="sub">{vm} · {att}</div>
<div class="meta"><span class="ok">healthy</span> · uptime {up} · {count} workload(s){terminal_link}</div>
<div class="cards">
  <div class="card"><div class="label">CPU</div><div class="value green">{cpu}%</div></div>
  <div class="card"><div class="label">Memory</div><div class="value blue">{mu} / {mt}</div></div>
  <div class="card"><div class="label">Load 1m</div><div class="value mauve">{load:.2}</div></div>
</div>
{oracle_section}
<div class="section">Workloads</div>{table}"#,
        terminal_link = terminal_link,
        oracle_section = oracle_section,
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

async fn api_sessions(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Vec<crate::sessiond::SessionMeta>>> {
    ensure_browser_auth(&s, &headers, &uri)?;
    sessiond_get(&s, "/api/sessions").await.map(Json)
}

async fn create_session(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<crate::sessiond::CreateSession>,
) -> Result<Json<crate::sessiond::CreateSessionResponse>> {
    ensure_browser_auth(&s, &headers, &uri)?;
    sessiond_post(&s, "/api/sessions", &req).await.map(Json)
}

async fn replay_session(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
) -> Result<Json<crate::sessiond::ReplayResponse>> {
    ensure_browser_auth(&s, &headers, &uri)?;
    sessiond_get(&s, &format!("/api/sessions/{id}/replay"))
        .await
        .map(Json)
}

async fn resize_session(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    Json(req): Json<crate::sessiond::ResizeSession>,
) -> Result<axum::http::StatusCode> {
    ensure_browser_auth(&s, &headers, &uri)?;
    sessiond_post_empty_json(&s, &format!("/api/sessions/{id}/resize"), &req).await
}

async fn close_session(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode> {
    ensure_browser_auth(&s, &headers, &uri)?;
    sessiond_post_empty(&s, &format!("/api/sessions/{id}/close")).await
}

async fn attach_session(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    Query(query): Query<AttachQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    ensure_browser_auth(&s, &headers, &uri)?;
    let attach_addr = s.sessiond_attach_addr.clone();
    Ok(ws.on_upgrade(move |socket| async move {
        if let Err(e) =
            attach_to_sessiond(socket, attach_addr, id, query.tail.unwrap_or(true)).await
        {
            eprintln!("agent: session attach ended: {e:#}");
        }
    }))
}

#[derive(Debug, Deserialize)]
struct CreateDeviceReq {
    pubkey: String,
    label: String,
}

/// POST /api/v1/devices — enroll a device pubkey on this agent.
/// Idempotent on pubkey: re-posting with a new label replaces the record.
async fn create_device(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Json(req): Json<CreateDeviceReq>,
) -> Result<(axum::http::StatusCode, Json<crate::devices::Device>)> {
    ensure_browser_auth(&s, &headers, &uri)?;
    let pubkey = req.pubkey.to_lowercase();
    crate::devices::validate_hex_pubkey(&pubkey).map_err(|e| Error::BadRequest(e.to_string()))?;
    let label = req.label.trim().to_string();
    if label.is_empty() || label.len() > 128 {
        return Err(Error::BadRequest("label must be 1..=128 chars".into()));
    }
    let device = crate::devices::Device {
        pubkey,
        label,
        created_at_ms: chrono::Utc::now().timestamp_millis(),
        revoked_at_ms: None,
    };
    s.devices
        .upsert(device.clone())
        .await
        .map_err(|e| Error::Internal(format!("devices upsert: {e}")))?;
    Ok((axum::http::StatusCode::CREATED, Json(device)))
}

/// DELETE /api/v1/devices/{pubkey} — revoke a paired device on this agent.
async fn revoke_device(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Path(pubkey): Path<String>,
) -> Result<Json<serde_json::Value>> {
    ensure_browser_auth(&s, &headers, &uri)?;
    let pubkey = pubkey.to_lowercase();
    let now = chrono::Utc::now().timestamp_millis();
    let ok = s
        .devices
        .revoke(&pubkey, now)
        .await
        .map_err(|e| Error::Internal(format!("devices revoke: {e}")))?;
    if !ok {
        return Err(Error::NotFound);
    }
    Ok(Json(serde_json::json!({
        "revoked": pubkey,
        "at_ms": now,
    })))
}

/// GET /admin/enroll?pubkey=...&label=... — authenticated confirmation
/// page. The mutation lands on this agent, so CP does not own paired-device
/// trust.
async fn enroll_page(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Some(resp) = require_browser_auth(&s, &headers, &uri) {
        return resp;
    }
    let pubkey = q.get("pubkey").cloned().unwrap_or_default();
    let label = q.get("label").cloned().unwrap_or_default();

    if let Err(e) = crate::devices::validate_hex_pubkey(&pubkey) {
        return Html(shell(
            "Enroll device",
            "",
            &format!(
                r#"<div class="card"><h1>Invalid pubkey</h1><p class="dim">{}</p></div>"#,
                html::escape(&e.to_string())
            ),
        ))
        .into_response();
    }
    if label.trim().is_empty() || label.len() > 128 {
        return Html(shell(
            "Enroll device",
            "",
            r#"<div class="card"><h1>Invalid label</h1><p class="dim">label must be 1..=128 chars</p></div>"#,
        ))
        .into_response();
    }

    let short = &pubkey[..16];
    let body = format!(
        r#"<div class="card">
  <h1>Enroll this device?</h1>
  <div class="row"><span>Label</span><span>{label}</span></div>
  <div class="row"><span>Pubkey</span><code>{short}...</code></div>
  <p class="dim">
    Confirming adds this X25519 public key to this agent's trust list. A
    client holding the matching private key can open Noise_IK sessions to this
    enclave. Revoke with <code>DELETE /api/v1/devices/&lt;pubkey&gt;</code>.
  </p>
  <p id="status"></p>
  <div style="display:flex;gap:8px">
    <button id="confirm" class="ok">Confirm</button>
    <a href="/" class="btn">Cancel</a>
  </div>
</div>
<script>
  const pubkey = {pubkey_js};
  const label  = {label_js};
  const status = document.getElementById("status");
  document.getElementById("confirm").addEventListener("click", async (ev) => {{
    ev.target.disabled = true;
    status.textContent = "Enrolling...";
    try {{
      const resp = await fetch("/api/v1/devices", {{
        method: "POST",
        credentials: "same-origin",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify({{ pubkey, label }}),
      }});
      if (!resp.ok) {{
        const text = await resp.text();
        status.innerHTML = "<span class='err'>Enrollment failed: " +
          resp.status + " " + text.slice(0, 400).replace(/</g, "&lt;") +
          "</span>";
        ev.target.disabled = false;
        return;
      }}
      status.innerHTML = "<span class='ok'>Enrolled - you can close this tab</span>";
    }} catch (e) {{
      status.innerHTML = "<span class='err'>Network error: " + String(e) + "</span>";
      ev.target.disabled = false;
    }}
  }});
</script>"#,
        label = html::escape(&label),
        short = html::escape(short),
        pubkey_js = serde_json::to_string(&pubkey).unwrap_or_else(|_| "\"\"".into()),
        label_js = serde_json::to_string(&label).unwrap_or_else(|_| "\"\"".into()),
    );

    Html(shell("Enroll device", "", &body)).into_response()
}

#[derive(Debug, Deserialize)]
struct AttachQuery {
    tail: Option<bool>,
}

fn ensure_browser_auth(s: &St, headers: &HeaderMap, uri: &Uri) -> Result<()> {
    if require_browser_auth(s, headers, uri).is_some() {
        Err(Error::Unauthorized)
    } else {
        Ok(())
    }
}

async fn attach_to_sessiond(
    socket: WebSocket,
    attach_addr: String,
    id: String,
    tail: bool,
) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(&attach_addr).await?;
    let tail_arg = if tail { "tail" } else { "notail" };
    stream
        .write_all(format!("{id} {tail_arg}\n").as_bytes())
        .await?;
    let (mut tcp_rx, mut tcp_tx) = stream.into_split();
    let (mut ws_tx, mut ws_rx) = socket.split();

    let output = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = match tcp_rx.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if ws_tx
                .send(Message::Binary(buf[..n].to_vec().into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    while let Some(msg) = ws_rx.next().await {
        match msg? {
            Message::Binary(bytes) => tcp_tx.write_all(&bytes).await?,
            Message::Text(text) => tcp_tx.write_all(text.as_bytes()).await?,
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => {}
        }
    }
    output.abort();
    Ok(())
}

async fn sessiond_get<T: DeserializeOwned>(s: &St, path: &str) -> Result<T> {
    let url = format!("{}{}", s.sessiond_http_url.trim_end_matches('/'), path);
    let resp = s.http.get(url).send().await?;
    decode_sessiond_response(path, resp).await
}

async fn sessiond_post<T: DeserializeOwned, B: serde::Serialize>(
    s: &St,
    path: &str,
    body: &B,
) -> Result<T> {
    let url = format!("{}{}", s.sessiond_http_url.trim_end_matches('/'), path);
    let resp = s.http.post(url).json(body).send().await?;
    decode_sessiond_response(path, resp).await
}

async fn sessiond_post_empty(s: &St, path: &str) -> Result<axum::http::StatusCode> {
    let url = format!("{}{}", s.sessiond_http_url.trim_end_matches('/'), path);
    let resp = s.http.post(url).send().await?;
    decode_sessiond_empty(path, resp).await
}

async fn sessiond_post_empty_json<B: serde::Serialize>(
    s: &St,
    path: &str,
    body: &B,
) -> Result<axum::http::StatusCode> {
    let url = format!("{}{}", s.sessiond_http_url.trim_end_matches('/'), path);
    let resp = s.http.post(url).json(body).send().await?;
    decode_sessiond_empty(path, resp).await
}

async fn decode_sessiond_response<T: DeserializeOwned>(
    path: &str,
    resp: reqwest::Response,
) -> Result<T> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Upstream(format!(
            "sessiond {path}: HTTP {status}: {body}"
        )));
    }
    Ok(resp.json().await?)
}

async fn decode_sessiond_empty(
    path: &str,
    resp: reqwest::Response,
) -> Result<axum::http::StatusCode> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::Upstream(format!(
            "sessiond {path}: HTTP {status}: {body}"
        )));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn api_oracles(State(s): State<St>) -> Json<Vec<oracle::OracleStatus>> {
    Json(s.oracles.read().await.clone())
}

async fn api_units(State(s): State<St>) -> Json<Vec<ManagedUnit>> {
    let list = s.ee.list().await.unwrap_or_default();
    let oracles = s.oracles.read().await.clone();
    let taint_reasons = s.taint.snapshot().await;
    let integrity_state = IntegrityState::from_taint_reasons(&taint_reasons);
    let agent_mode = AgentMode::from_confidential(s.cfg.confidential);
    Json(managed_units(&s, &list, &oracles, agent_mode, integrity_state).await)
}

async fn managed_units(
    s: &St,
    list: &serde_json::Value,
    oracles: &[oracle::OracleStatus],
    agent_mode: AgentMode,
    agent_integrity_state: IntegrityState,
) -> Vec<ManagedUnit> {
    let mut oracle_by_app: std::collections::HashMap<String, oracle::OracleStatus> = oracles
        .iter()
        .cloned()
        .map(|oracle| (oracle.app_name.clone(), oracle))
        .collect();
    let mut out = Vec::new();
    if let Some(deployments) = list["deployments"].as_array() {
        for d in deployments {
            let Some(app_name) = d["app_name"].as_str() else {
                continue;
            };
            let id = d["id"].as_str().unwrap_or(app_name).to_string();
            let oracle = oracle_by_app.remove(app_name);
            let kind = units::kind_for_app(app_name);
            let log_line_count = workload_log_line_count(&s.ee, &id).await;
            let mut capabilities = units::base_capabilities(kind);
            if kind == UnitKind::Agent && agent_mode == AgentMode::ReadWrite {
                capabilities.extend(["deploy".into(), "exec".into()]);
            }
            capabilities.push("logs".into());
            if oracle.is_some() {
                capabilities.push("oracle".into());
            }
            let refs = unit_refs(s, app_name, kind, oracle.as_ref()).await;
            let title = oracle
                .as_ref()
                .map(|oracle| oracle.title.clone())
                .unwrap_or_else(|| units::title_for_app(app_name));
            out.push(ManagedUnit {
                id,
                app_name: app_name.to_string(),
                title,
                kind,
                agent_mode,
                agent_integrity_state,
                status: d["status"].as_str().unwrap_or("unknown").to_string(),
                image: non_empty_string(&d["image"]),
                started_at: non_empty_string(&d["started_at"]),
                error_message: non_empty_string(&d["error_message"]),
                source: units::source_for_app(app_name),
                log_line_count,
                capabilities,
                refs,
                oracle,
            });
        }
    }

    for oracle in oracle_by_app.into_values() {
        let refs = unit_refs(s, &oracle.app_name, UnitKind::Workload, Some(&oracle)).await;
        out.push(ManagedUnit {
            id: oracle.app_name.clone(),
            app_name: oracle.app_name.clone(),
            title: oracle.title.clone(),
            kind: UnitKind::Workload,
            agent_mode,
            agent_integrity_state,
            status: oracle.status.clone(),
            image: None,
            started_at: None,
            error_message: oracle.last_error.clone(),
            source: units::source_for_app(&oracle.app_name),
            log_line_count: 0,
            capabilities: vec!["oracle".into()],
            refs,
            oracle: Some(oracle),
        });
    }
    out.sort_by(|a, b| a.app_name.cmp(&b.app_name));
    out
}

async fn unit_refs(
    s: &St,
    app_name: &str,
    kind: UnitKind,
    oracle: Option<&oracle::OracleStatus>,
) -> Vec<units::UnitRef> {
    let mut refs = Vec::new();
    if let Some(source) = units::source_for_app(app_name) {
        refs.push(units::ref_item("source", "source", source));
    }
    match kind {
        UnitKind::Agent => {
            refs.push(units::ref_item(
                "url",
                "dashboard",
                format!("https://{}", s.hostname),
            ));
            refs.push(units::ref_item(
                "url",
                "agent-api",
                format!("https://{}", crate::cf::agent_api_hostname(&s.hostname)),
            ));
        }
        UnitKind::Shell => refs.push(units::ref_item(
            "url",
            "shell",
            format!(
                "https://{}",
                crate::cf::label_hostname(&s.hostname, "shell")
            ),
        )),
        UnitKind::Tunnel => {
            refs.push(units::ref_item(
                "url",
                "dashboard",
                format!("https://{}", s.hostname),
            ));
            refs.push(units::ref_item(
                "url",
                "agent-api",
                format!("https://{}", crate::cf::agent_api_hostname(&s.hostname)),
            ));
            for (label, port) in s.extras.read().await.iter() {
                refs.push(units::ref_item(
                    "ingress",
                    label,
                    format!(
                        "https://{} -> localhost:{port}",
                        crate::cf::label_hostname(&s.hostname, label)
                    ),
                ));
            }
        }
        UnitKind::Storage | UnitKind::Runtime | UnitKind::Workload => {}
    }
    if let Some(oracle) = oracle {
        if let Some(url) = &oracle.vanity_url {
            refs.push(units::ref_item("url", "oracle", url.clone()));
        }
        refs.push(units::ref_item(
            "url",
            "oracle-local",
            oracle.local_url.clone(),
        ));
    }
    refs
}

async fn workload_log_line_count(ee: &Ee, id: &str) -> usize {
    match ee.logs(id).await {
        Ok(logs) => logs["lines"].as_array().map(|a| a.len()).unwrap_or(0),
        Err(e) => {
            eprintln!("agent: log count unavailable for {id}: {e}");
            0
        }
    }
}

async fn recent_log_lines_html(ee: &Ee, id: &str, limit: usize) -> String {
    match ee.logs(id).await {
        Ok(logs) => {
            let Some(lines) = logs["lines"].as_array() else {
                return r#"<span class="dim">No logs captured yet</span>"#.into();
            };
            let start = lines.len().saturating_sub(limit);
            let text = lines[start..]
                .iter()
                .filter_map(|v| v.as_str())
                .map(html::escape)
                .collect::<Vec<_>>()
                .join("\n");
            if text.is_empty() {
                r#"<span class="dim">No logs captured yet</span>"#.into()
            } else {
                text
            }
        }
        Err(e) => {
            eprintln!("agent: recent logs unavailable for {id}: {e}");
            format!(
                r#"<span style="color:#f38ba8">Log capture unavailable: {}</span>"#,
                html::escape(&e.to_string())
            )
        }
    }
}

fn status_class(status: &str) -> &'static str {
    match status {
        "healthy" | "running" => "running",
        "deploying" | "unknown" | "stale" => "deploying",
        "error" | "failed" | "exited" | "dead" => "failed",
        _ => "idle",
    }
}

fn integrity_label(integrity_state: IntegrityState) -> &'static str {
    match integrity_state {
        IntegrityState::Clean => "clean",
        IntegrityState::Controlled => "controlled",
    }
}

fn non_empty_string(value: &serde_json::Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

async fn workload_page(
    State(s): State<St>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
) -> Result<Response> {
    if let Some(resp) = require_browser_auth(&s, &headers, &uri) {
        return Ok(resp);
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
    // Log entry before auth so OIDC failures show up with agent-side
    // context instead of just a caller-side HTTP reject.
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
    let resp = crate::system_http_client()
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
