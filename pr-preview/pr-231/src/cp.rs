//! Control plane.
//!
//! WIP — this is the post-rewrite skeleton. The full set of routes
//! (deployment CRUD with workload dispatch, full registration round
//! trip, OAuth-gated dashboard) lands incrementally. Today this binds
//! the HTTP server, wires the OAuth + auth middleware, exposes
//! deployment reads via `cf::list_cnames` (DNS = source of truth), and
//! stubs the write paths.

use std::sync::Arc;

use axum::{
    extract::{FromRef, Path, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post},
    Router,
};
use tokio::net::TcpListener;

use crate::auth::{self, CookieAuthState};
use crate::config::Cp as Config;
use crate::deployment;
use crate::error::Result;
use crate::oauth::{self, OauthState};

#[derive(Clone)]
pub struct St {
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub oauth: OauthState,
    pub cookie_auth: CookieAuthState,
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
        .map_err(|e| crate::error::Error::Internal(format!("http client: {e}")))?;
    let oauth_state = OauthState::from_cp(&cfg, &cfg.common, http.clone());
    let cookie_auth = CookieAuthState {
        fleet_jwt_secret: cfg.common.fleet_jwt_secret.clone(),
        expected_fleet: cfg.common.owner.name.clone(),
        login_url: format!("https://{}/login", cfg.hostname),
    };

    let st = St {
        cfg: cfg.clone(),
        http,
        oauth: oauth_state,
        cookie_auth,
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
        .map_err(|e| crate::error::Error::Internal(format!("axum serve: {e}")))?;
    Ok(())
}

async fn root(State(s): State<St>, headers: HeaderMap) -> Response {
    // Best-effort cookie check using the manual verifier so we can
    // redirect (rather than 401) when no cookie is present.
    let authed = headers
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
        .unwrap_or(false);

    if authed {
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

async fn api_agents(State(_): State<St>) -> Json<serde_json::Value> {
    // TODO: enumerate agents from CF tunnel list once the registration
    // round-trip is implemented.
    Json(serde_json::json!([]))
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
        .ok_or(crate::error::Error::NotFound)?;
    Ok(Json(serde_json::json!(d)))
}

async fn create_deployment(
    State(_): State<St>,
    Json(_body): Json<deployment::CreateDeployment>,
) -> Result<Json<serde_json::Value>> {
    // TODO: validate workload, pick host, send /deploy to host agent,
    // upsert CNAME, upsert TXT for non-default failover policy.
    Err(crate::error::Error::Internal(
        "create_deployment not yet implemented".into(),
    ))
}

async fn delete_deployment(
    State(s): State<St>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>> {
    crate::cf::delete_cname(&s.http, &s.cfg.cf, &name).await?;
    let _ = crate::cf::delete_txt(&s.http, &s.cfg.cf, &format!("_dd.{name}")).await;
    Ok(Json(serde_json::json!({"deleted": name})))
}

async fn register(State(_): State<St>) -> Result<Json<serde_json::Value>> {
    // TODO: ITA verification + per-agent tunnel provisioning.
    Err(crate::error::Error::Internal(
        "register not yet implemented".into(),
    ))
}
