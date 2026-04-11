use axum::routing::get;
use axum::Router;

use crate::state::WebState;
use crate::{auth, federate, fleet};

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "ok": true,
        "service": "dd-web",
    }))
}

pub fn build_router(state: WebState) -> Router {
    Router::new()
        .route("/", get(fleet::fleet_dashboard))
        .route("/health", get(health))
        .route("/agent/{id}", get(fleet::agent_detail))
        .route("/federate", get(federate::federate))
        .route("/auth/github/start", get(auth::github_start))
        .route("/auth/github/callback", get(auth::github_callback))
        .route("/auth/logout", get(auth::logout))
        .route("/logged-out", get(auth::logged_out_page))
        .with_state(state)
}
