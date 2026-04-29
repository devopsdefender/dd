//! Agent mode.
//!
//! Boot sequence:
//!   1. Mint our own ITA token via easyenclave's `attest`.
//!   2. POST /register to the CP, receive {agent_id, hostname,
//!      tunnel_token}.
//!   3. Spawn cloudflared with the tunnel token (subprocess).
//!   4. Bind HTTP on `$DD_PORT`, serve until killed.
//!
//! Routes:
//!   - `/health` — JSON status (unauth).
//!   - `/manifest` — workload manifest + Noise pubkey for client pinning (unauth).
//!   - `/deploy` — receive workload from CP / CI (GH-OIDC or fleet-CP JWT).
//!   - `/log`, `/log/pubkey` — oracle public log (unauth).
//!   - `/dd/log/append` — loopback only.
//!   - `/history`, `/dd/history/...` — confidential history (read = cookie; loopback write).
//!   - `/noise` — WSS Noise gateway (handshake gates traffic).
//!   - `/session/shell` — PTY bridge (cookie-gated for shell-kind workloads).

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{FromRef, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::auth::{CookieAuthState, Identity};
use crate::config::Agent as Config;
use crate::ee::Ee;
use crate::error::{Error, Result};
use crate::history::{self, HistoryStore};
use crate::kinds::{bot, oracle, shell};
use crate::log::{self, LogStore};
use crate::noise::{self, NoiseGateway};
use crate::workload::{Kind, KindConfig, Workload};

/// One-shot per-deployment state. v1: at most one Deployment per agent.
#[derive(Clone)]
pub struct DeployedState {
    pub workload: Workload,
    pub vanity: Option<String>,
    pub upstream_origin: String,
    pub noise: NoiseGateway,
    pub history: Option<HistoryStore>,
    pub log: Option<LogStore>,
}

#[derive(Clone)]
pub struct St {
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub cookie_auth: CookieAuthState,
    pub deployed: Arc<RwLock<Option<DeployedState>>>,
    pub ee: Arc<Ee>,
}

impl FromRef<St> for CookieAuthState {
    fn from_ref(s: &St) -> Self {
        s.cookie_auth.clone()
    }
}

pub async fn run() -> Result<()> {
    let cfg = Arc::new(Config::from_env()?);
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Internal(format!("http client: {e}")))?;
    let cookie_auth = CookieAuthState {
        fleet_jwt_secret: cfg.common.fleet_jwt_secret.clone(),
        expected_fleet: cfg.common.owner.name.clone(),
        login_url: format!("{}/login", cfg.cp_url.trim_end_matches('/')),
    };

    let ee = Arc::new(Ee::new(&cfg.ee_socket));

    let st = St {
        cfg: cfg.clone(),
        http: http.clone(),
        cookie_auth,
        deployed: Arc::new(RwLock::new(None)),
        ee,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/manifest", get(manifest))
        .route("/deploy", post(deploy))
        .route("/log", get(log_read))
        .route("/log/pubkey", get(log_pubkey))
        .route("/dd/log/append", post(log_append_loopback))
        .route("/history", get(history_read).delete(history_clear))
        .route("/dd/history/append", post(history_append_loopback))
        .route("/noise", get(noise_ws))
        .route("/session/shell", get(session_shell))
        .with_state(st);

    let port = cfg.common.port;
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    eprintln!("agent: listening on :{port}");
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::Internal(format!("axum serve: {e}")))?;
    Ok(())
}

// ─── Routes ────────────────────────────────────────────────────────────

async fn health(State(s): State<St>) -> Json<serde_json::Value> {
    let dep = s.deployed.read().await;
    let kind = dep.as_ref().map(|d| d.workload.kind.as_str());
    let name = dep.as_ref().map(|d| d.workload.name.clone());
    Json(serde_json::json!({
        "ok": true,
        "mode": "agent",
        "vm_name": s.cfg.common.vm_name,
        "kind": kind,
        "deployment": name,
    }))
}

async fn manifest(State(s): State<St>) -> Response {
    let dep = s.deployed.read().await;
    match dep.as_ref() {
        Some(d) => {
            let mut m = serde_json::json!({
                "kind": d.workload.kind.as_str(),
                "name": d.workload.name,
                "noise_pubkey_b64": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    d.noise.public_key(),
                ),
            });
            if let KindConfig::Oracle {
                signer_env: Some(env),
                ..
            } = &d.workload.kind_config
            {
                m["signer_env"] = serde_json::json!(env);
            }
            // For oracles, expose the workload's full attestation manifest.
            if d.workload.kind == Kind::Oracle {
                let om = oracle::OracleManifest::from_workload(&d.workload);
                if let Ok(v) = serde_json::to_value(&om) {
                    m["oracle"] = v;
                }
            }
            Json(m).into_response()
        }
        None => (StatusCode::NOT_FOUND, "no deployment").into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct DeployBody {
    #[serde(default)]
    vanity: Option<String>,
    workload: Workload,
}

async fn deploy(State(s): State<St>, headers: HeaderMap, Json(body): Json<DeployBody>) -> Response {
    if let Err(e) = require_deploy_auth(&s, &headers) {
        return (StatusCode::UNAUTHORIZED, e.to_string()).into_response();
    }
    if let Err(e) = body.workload.validate() {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    match deploy_inner(&s, body).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn deploy_inner(s: &St, body: DeployBody) -> Result<()> {
    let w = body.workload;

    // Tell EE to run the container.
    let ee_spec = serde_json::to_value(&w)?;
    s.ee.deploy(ee_spec).await?;

    // Per-deployment state for the in-binary handlers.
    let upstream_port = w.primary_port();
    let upstream_origin = format!("http://127.0.0.1:{upstream_port}");

    // Noise keypair: derived from a per-deployment seed. v1 uses a
    // deterministic seed of fleet_jwt_secret || workload.name so the
    // same name on the same fleet produces the same pubkey across
    // restarts. Will become a TDX-bound sealed-key-derive once EE
    // exposes one.
    let mut seed = [0u8; 32];
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(s.cfg.common.fleet_jwt_secret.as_bytes());
        h.update(b"|");
        h.update(w.name.as_bytes());
        seed.copy_from_slice(&h.finalize());
    }
    let (priv_key, _pub_key) = noise::keypair_from_seed(seed);
    let noise_gw = NoiseGateway::from_keypair(priv_key, upstream_origin.clone());

    // Optional history store.
    let history_store = match &w.kind_config {
        KindConfig::Bot {
            history: Some(h), ..
        }
        | KindConfig::Llm {
            history: Some(h), ..
        }
        | KindConfig::Shell {
            history: Some(h), ..
        } => {
            let path: PathBuf = format!("/var/lib/dd/history/{}.jsonl", w.name).into();
            Some(HistoryStore::from_pubkey_b64(&h.client_pubkey, path)?)
        }
        _ => None,
    };

    // Optional public log store (oracle only).
    let log_store = match &w.kind_config {
        KindConfig::Oracle {
            public_log: true, ..
        } => {
            let path: PathBuf = format!("/var/lib/dd/log/{}.ndjson", w.name).into();
            // Same per-deployment seed strategy: deterministic from
            // fleet_jwt_secret || workload.name. Verifiers pin the
            // resulting pubkey via /log/pubkey paired with the ITA quote.
            let mut log_seed = [0u8; 32];
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(s.cfg.common.fleet_jwt_secret.as_bytes());
            h.update(b"|log|");
            h.update(w.name.as_bytes());
            log_seed.copy_from_slice(&h.finalize());
            Some(LogStore::from_seed(log_seed, path))
        }
        _ => None,
    };

    // Optional bot wake schedule.
    if let Some(sched_str) = bot::extract_schedule(&w) {
        if let Some(period) = bot::parse_schedule(sched_str) {
            let url = format!("{}/tick", upstream_origin);
            let http = s.http.clone();
            tokio::spawn(async move {
                bot::wake_loop(http, url, period).await;
            });
        }
    }

    *s.deployed.write().await = Some(DeployedState {
        workload: w,
        vanity: body.vanity,
        upstream_origin,
        noise: noise_gw,
        history: history_store,
        log: log_store,
    });
    Ok(())
}

async fn log_read(State(s): State<St>) -> Response {
    let dep = s.deployed.read().await;
    match dep.as_ref().and_then(|d| d.log.clone()) {
        Some(store) => match log::read_all(&store).await {
            Ok(entries) => {
                let mut body = String::new();
                for e in entries {
                    if let Ok(line) = serde_json::to_string(&e) {
                        body.push_str(&line);
                        body.push('\n');
                    }
                }
                (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
                    body,
                )
                    .into_response()
            }
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        None => (StatusCode::NOT_FOUND, "public log not enabled").into_response(),
    }
}

async fn log_pubkey(State(s): State<St>) -> Response {
    use base64::Engine;
    let dep = s.deployed.read().await;
    match dep.as_ref().and_then(|d| d.log.clone()) {
        Some(store) => {
            let vk = store.verifying_key();
            Json(serde_json::json!({
                "alg": "ed25519",
                "pubkey_b64": base64::engine::general_purpose::STANDARD.encode(vk.to_bytes()),
                "pubkey_hex": hex::encode(vk.to_bytes()),
            }))
            .into_response()
        }
        None => (StatusCode::NOT_FOUND, "public log not enabled").into_response(),
    }
}

async fn log_append_loopback(
    State(s): State<St>,
    headers: HeaderMap,
    Json(body): Json<log::AppendBody>,
) -> Response {
    if !is_loopback(&headers) {
        return (StatusCode::FORBIDDEN, "loopback only").into_response();
    }
    let dep = s.deployed.read().await;
    match dep.as_ref().and_then(|d| d.log.clone()) {
        Some(store) => match log::append(&store, body.content).await {
            Ok(entry) => Json(entry).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        None => (StatusCode::BAD_REQUEST, "public log not enabled").into_response(),
    }
}

async fn history_read(
    State(s): State<St>,
    _ident: Identity,
    axum::extract::Query(q): axum::extract::Query<history::ReadQuery>,
) -> Response {
    let dep = s.deployed.read().await;
    match dep.as_ref().and_then(|d| d.history.clone()) {
        Some(store) => match history::read_all(&store, q.since).await {
            Ok(entries) => Json(entries).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        None => (StatusCode::NOT_FOUND, "history not enabled").into_response(),
    }
}

async fn history_clear(State(s): State<St>, _ident: Identity) -> Response {
    let dep = s.deployed.read().await;
    match dep.as_ref().and_then(|d| d.history.clone()) {
        Some(store) => match history::clear(&store).await {
            Ok(_) => (StatusCode::NO_CONTENT, "").into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        None => (StatusCode::NOT_FOUND, "history not enabled").into_response(),
    }
}

async fn history_append_loopback(
    State(s): State<St>,
    headers: HeaderMap,
    Json(body): Json<history::AppendBody>,
) -> Response {
    if !is_loopback(&headers) {
        return (StatusCode::FORBIDDEN, "loopback only").into_response();
    }
    let dep = s.deployed.read().await;
    match dep.as_ref().and_then(|d| d.history.clone()) {
        Some(store) => match history::append(&store, body.plaintext.as_bytes()).await {
            Ok(entry) => Json(entry).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        None => (StatusCode::BAD_REQUEST, "history not enabled").into_response(),
    }
}

async fn noise_ws(State(s): State<St>, ws: WebSocketUpgrade) -> Response {
    let dep = s.deployed.read().await;
    match dep.as_ref().map(|d| d.noise.clone()) {
        Some(gw) => noise::handler(State(gw), ws).await,
        None => (StatusCode::NOT_FOUND, "no deployment").into_response(),
    }
}

async fn session_shell(State(s): State<St>, ident: Identity, ws: WebSocketUpgrade) -> Response {
    let dep = s.deployed.read().await;
    let dep = match dep.as_ref() {
        Some(d) => d,
        None => return (StatusCode::NOT_FOUND, "no deployment").into_response(),
    };
    if dep.workload.kind != Kind::Shell {
        return (StatusCode::NOT_FOUND, "not a shell-kind deployment").into_response();
    }
    let policy = match shell::ShellPolicy::from_workload(&dep.workload) {
        Some(p) => p,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "shell policy parse").into_response(),
    };
    if !policy.permits(&ident) {
        return (StatusCode::FORBIDDEN, "user not in allowed_users").into_response();
    }
    let ee = s.ee.clone();
    ws.on_upgrade(move |socket| async move {
        match ee.attach(&["/bin/bash".into()]).await {
            Ok(pty) => shell::bridge_pty(socket, pty, policy).await,
            Err(e) => eprintln!("shell attach: {e}"),
        }
    })
}

// ─── Helpers ───────────────────────────────────────────────────────────

fn is_loopback(headers: &HeaderMap) -> bool {
    // Loopback: the request came from inside the agent's own VM. We
    // accept any of:
    //   - X-Forwarded-For with 127.0.0.1
    //   - no X-Forwarded-For at all (direct local socket)
    // axum extracts the remote addr separately; v1 trusts the
    // X-Forwarded-For check.
    match headers.get("x-forwarded-for") {
        Some(v) => v
            .to_str()
            .map(|s| s.contains("127.0.0.1") || s.contains("::1"))
            .unwrap_or(true),
        None => true,
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct CpJwtClaims {
    sub: String,
    fleet: String,
    exp: i64,
}

/// Accept either:
///   - GH OIDC bearer (CI workflows)
///   - Fleet-CP HS256 JWT bearer (CP-driven deploy traffic)
fn require_deploy_auth(s: &St, headers: &HeaderMap) -> Result<()> {
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(Error::Unauthorized)?;

    // Try fleet-CP JWT first (cheap, in-memory verify).
    let mut v = Validation::new(Algorithm::HS256);
    v.set_required_spec_claims(&["sub", "exp"]);
    v.leeway = 30;
    if let Ok(data) = jsonwebtoken::decode::<CpJwtClaims>(
        bearer,
        &DecodingKey::from_secret(s.cfg.common.fleet_jwt_secret.as_bytes()),
        &v,
    ) {
        if data.claims.sub == "__cp__" && data.claims.fleet == s.cfg.common.owner.name {
            return Ok(());
        }
    }

    // GH OIDC fallback would go here. v1 simplification: rely on the
    // CP for OIDC verification (CI calls /cp/deployments, CP forwards
    // with the __cp__ JWT to agents). Direct CI → agent calls aren't
    // the headline path; deferred.
    Err(Error::Unauthorized)
}
