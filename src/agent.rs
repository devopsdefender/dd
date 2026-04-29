//! Agent mode.
//!
//! WIP — post-rewrite skeleton. Today: bind HTTP, expose `/health`,
//! verify the human cookie via `auth.rs` middleware. Full kind
//! handlers (`/session/shell` PTY bridge, `/llm/*` proxy, `/manifest`,
//! `/history`, `/log`, etc.) land incrementally.

use std::sync::Arc;

use axum::{
    extract::{FromRef, State},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use tokio::net::TcpListener;

use crate::auth::CookieAuthState;
use crate::config::Agent as Config;
use crate::error::Result;

#[derive(Clone)]
pub struct St {
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub cookie_auth: CookieAuthState,
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

    // Cookie verification points humans at the CP's `/login`. The
    // domain part (everything after the first dot in cp_url) is what
    // `Domain=.<fleet-domain>` cookies are scoped to.
    let cookie_auth = CookieAuthState {
        fleet_jwt_secret: cfg.common.fleet_jwt_secret.clone(),
        expected_fleet: cfg.common.owner.name.clone(),
        login_url: format!("{}/login", cfg.cp_url.trim_end_matches('/')),
    };

    let st = St {
        cfg: cfg.clone(),
        http,
        cookie_auth,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/deploy", post(deploy))
        .with_state(st);

    let port = cfg.common.port;
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    eprintln!("agent: listening on :{port}");
    axum::serve(listener, app)
        .await
        .map_err(|e| crate::error::Error::Internal(format!("axum serve: {e}")))?;
    Ok(())
}

async fn health(State(_): State<St>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "mode": "agent"}))
}

async fn deploy(State(_): State<St>) -> impl IntoResponse {
    // TODO: GH-OIDC verify, validate Workload, dispatch to EE based on kind.
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "deploy not yet implemented",
    )
}
