//! Control plane.
//!
//! HTTP server that:
//! * boots its own CF tunnel + mints its own ITA token
//! * hosts the GitHub OAuth login (`/login`, `/oauth/callback`,
//!   `/logout`)
//! * accepts agent registrations (`POST /register` — ITA-gated,
//!   provisions a per-agent CF tunnel)
//! * exposes the Deployment CRUD (`/cp/deployments`) — DNS is the
//!   source of truth, so reads list CNAMEs and writes upsert them
//! * pushes Deployment workloads to agents over their tunnels with
//!   a fleet-CP JWT bearer that agents recognise as system traffic
//!
//! No CF Access apps, no in-memory device store, no taint surface.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{FromRef, Path, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::auth::{self, CookieAuthState};
use crate::cf::{self};
use crate::config::Cp as Config;
use crate::deployment::{self, FailoverPolicyTxt};
use crate::error::{Error, Result};
use crate::ita::{Claims, Verifier};
use crate::oauth::{self, OauthState};

#[derive(Clone, Debug, Serialize)]
pub struct AgentRecord {
    pub vm_name: String,
    pub agent_id: String,
    pub hostname: String,
    pub tunnel_id: String,
    pub registered_at_ms: i64,
    pub last_seen_ms: i64,
    pub mrtd: Option<String>,
    pub tcb_status: Option<String>,
}

#[derive(Clone)]
pub struct St {
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub oauth: OauthState,
    pub cookie_auth: CookieAuthState,
    pub verifier: Arc<Verifier>,
    pub agents: Arc<RwLock<HashMap<String, AgentRecord>>>,
}

impl FromRef<St> for OauthState {
    fn from_ref(s: &St) -> Self {
        s.oauth.clone()
    }
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
    let oauth_state = OauthState::from_cp(&cfg, &cfg.common, http.clone());
    let cookie_auth = CookieAuthState {
        fleet_jwt_secret: cfg.common.fleet_jwt_secret.clone(),
        expected_fleet: cfg.common.owner.name.clone(),
        login_url: format!("https://{}/login", cfg.hostname),
    };
    let verifier = Verifier::new(cfg.ita.jwks_url.clone(), cfg.ita.issuer.clone());

    let st = St {
        cfg: cfg.clone(),
        http,
        oauth: oauth_state,
        cookie_auth,
        verifier,
        agents: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/login", get(oauth::login))
        .route("/oauth/callback", get(oauth::callback))
        .route("/logout", get(oauth::logout))
        .route("/api/agents", get(api_agents))
        .route(
            "/cp/deployments",
            get(list_deployments).post(create_deployment),
        )
        .route(
            "/cp/deployments/{name}",
            get(get_deployment).delete(delete_deployment),
        )
        .route("/register", post(register))
        .with_state(st);

    let port = cfg.common.port;
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    eprintln!("cp: listening on :{port}");
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::Internal(format!("axum serve: {e}")))?;
    Ok(())
}

// ─── Routes ────────────────────────────────────────────────────────────

async fn root(State(s): State<St>, headers: HeaderMap) -> Response {
    if cookie_authed(&s, &headers) {
        Html(
            "<!doctype html><meta charset=utf-8><title>dd</title>\
             <h1>devopsdefender</h1>\
             <p>Logged in. <a href='/api/agents'>agents</a> · \
             <a href='/cp/deployments'>deployments</a> · \
             <a href='/logout'>log out</a></p>",
        )
        .into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

async fn health(State(_): State<St>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "mode": "cp"}))
}

async fn api_agents(State(s): State<St>) -> Json<serde_json::Value> {
    let map = s.agents.read().await;
    let mut out: Vec<&AgentRecord> = map.values().collect();
    out.sort_by(|a, b| a.vm_name.cmp(&b.vm_name));
    Json(serde_json::json!(out))
}

async fn list_deployments(State(s): State<St>) -> Result<Json<serde_json::Value>> {
    let deployments = deployment::list(&s.http, &s.cfg.cf).await?;
    Ok(Json(serde_json::json!(deployments)))
}

async fn get_deployment(
    State(s): State<St>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let deployments = deployment::list(&s.http, &s.cfg.cf).await?;
    let d = deployments
        .into_iter()
        .find(|d| d.name == name)
        .ok_or(Error::NotFound)?;
    Ok(Json(serde_json::json!(d)))
}

#[derive(Debug, Deserialize)]
struct RegisterReq {
    vm_name: String,
    ita_token: String,
}

#[derive(Debug, Serialize)]
struct RegisterResp {
    agent_id: String,
    hostname: String,
    tunnel_token: String,
}

async fn register(State(s): State<St>, Json(req): Json<RegisterReq>) -> Result<Json<RegisterResp>> {
    if req.vm_name.is_empty() {
        return Err(Error::BadRequest("vm_name empty".into()));
    }
    let claims: Claims = s.verifier.verify(&req.ita_token).await?;
    let agent_id = uuid::Uuid::new_v4().to_string();
    let hostname = format!(
        "{}-{}.{}",
        s.cfg.common.env_label.replace('_', "-"),
        &agent_id[..8],
        s.cfg.cf.domain,
    );
    let tunnel = cf::create(
        &s.http,
        &s.cfg.cf,
        &cf::agent_tunnel_name(&s.cfg.common.env_label),
        &hostname,
        &[],
    )
    .await?;
    let now_ms = Utc::now().timestamp_millis();
    let record = AgentRecord {
        vm_name: req.vm_name.clone(),
        agent_id: agent_id.clone(),
        hostname: hostname.clone(),
        tunnel_id: tunnel.id.clone(),
        registered_at_ms: now_ms,
        last_seen_ms: now_ms,
        mrtd: claims.mrtd.clone(),
        tcb_status: claims.tcb_status.clone(),
    };
    s.agents.write().await.insert(agent_id.clone(), record);
    Ok(Json(RegisterResp {
        agent_id,
        hostname,
        tunnel_token: tunnel.token,
    }))
}

async fn create_deployment(
    State(s): State<St>,
    Json(body): Json<deployment::CreateDeployment>,
) -> Result<Json<serde_json::Value>> {
    body.workload.validate()?;
    if !body.vanity.contains('.') {
        return Err(Error::BadRequest(
            "vanity must be a fully-qualified hostname".into(),
        ));
    }

    // Pick a healthy host. v1 = first registered agent. Real failover
    // scheduling lands in collector.rs.
    let host = pick_host(&s).await?;

    // Push the workload to the agent over its tunnel. The bearer is a
    // short-lived JWT minted from the shared fleet secret with the
    // reserved `__cp__` subject — agents accept that subject as
    // system traffic.
    let cp_bearer = mint_cp_bearer(&s)?;
    let push_url = format!("https://{}/deploy", host.hostname);
    let resp = s
        .http
        .post(&push_url)
        .bearer_auth(&cp_bearer)
        .json(&serde_json::json!({
            "vanity": body.vanity,
            "workload": body.workload,
        }))
        .send()
        .await
        .map_err(|e| Error::Upstream(format!("push /deploy {push_url}: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        return Err(Error::Upstream(format!(
            "push /deploy {push_url}: {status}: {txt}"
        )));
    }

    // Vanity CNAME → agent hostname. The agent's tunnel must accept
    // the vanity hostname; the agent calls back to /cp/ingress to
    // request that. v1 simplification: agent's /deploy adds the
    // vanity to its own ingress before returning success.
    let target = format!("{}.cfargotunnel.com", host.tunnel_id);
    cf::upsert_cname_raw(&s.http, &s.cfg.cf, &body.vanity, &target).await?;

    // Persist the workload spec as an encrypted TXT record next to
    // the vanity. The collector uses this on failover so the new host
    // gets the real spec without the CP needing in-memory state.
    deployment::write_spec(
        &s.http,
        &s.cfg.cf,
        &s.cfg.common.fleet_jwt_secret,
        &body.vanity,
        &body.workload,
    )
    .await?;

    // Optional TXT for non-default failover policy.
    if let Some(pol) = body.failover.as_ref() {
        let txt = FailoverPolicyTxt::from_policy(pol);
        if !txt.is_empty() {
            let txt_name = format!("_dd.{}", body.vanity);
            let txt_body = serde_json::to_string(&txt)?;
            cf::upsert_txt(&s.http, &s.cfg.cf, &txt_name, &txt_body).await?;
        }
    }

    Ok(Json(serde_json::json!({
        "name": body.name,
        "vanity": body.vanity,
        "host_agent_id": host.agent_id,
        "host_hostname": host.hostname,
    })))
}

async fn delete_deployment(
    State(s): State<St>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>> {
    cf::delete_cname(&s.http, &s.cfg.cf, &name).await?;
    let _ = cf::delete_txt(&s.http, &s.cfg.cf, &format!("_dd.{name}")).await;
    let _ = deployment::delete_spec(&s.http, &s.cfg.cf, &name).await;
    Ok(Json(serde_json::json!({"deleted": name})))
}

// ─── Helpers ───────────────────────────────────────────────────────────

fn cookie_authed(s: &St, headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|hdr| {
            auth::parse_cookies(hdr)
                .find(|(k, _)| *k == auth::COOKIE_NAME)
                .map(|(_, v)| v.to_string())
        })
        .map(|tok| {
            auth::verify(
                &s.cookie_auth.fleet_jwt_secret,
                &tok,
                &s.cookie_auth.expected_fleet,
            )
            .is_ok()
        })
        .unwrap_or(false)
}

async fn pick_host(s: &St) -> Result<AgentRecord> {
    let map = s.agents.read().await;
    let now = Utc::now().timestamp_millis();
    let stale_ms: i64 = 5 * 60 * 1000;
    let mut healthy: Vec<&AgentRecord> = map
        .values()
        .filter(|a| now - a.last_seen_ms < stale_ms)
        .collect();
    healthy.sort_by_key(|a| a.last_seen_ms);
    healthy
        .last()
        .copied()
        .cloned()
        .ok_or(Error::Internal("no healthy agents".into()))
}

/// Mint a short-lived JWT signed with `DD_FLEET_JWT_SECRET` whose
/// subject is the reserved `__cp__` value. Agents accept this on
/// `/deploy` as system traffic.
pub fn mint_cp_bearer(s: &St) -> Result<String> {
    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "sub": "__cp__",
        "uid": 0,
        "fleet": s.cfg.common.owner.name,
        "iat": now,
        "exp": now + 60,
    });
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(s.cfg.common.fleet_jwt_secret.as_bytes()),
    )
    .map_err(|e| Error::Internal(format!("jwt mint: {e}")))
}
