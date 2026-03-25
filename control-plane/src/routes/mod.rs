pub mod accounts;
pub mod admin;
pub mod agents;
pub mod attestation;
pub mod auth;
pub mod deployments;
pub mod health;
pub mod stats;
pub mod ui;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::state::AppState;

/// Build the full Axum router with all routes.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Health
        .route("/health", get(health::health_check))
        // UI
        .route("/", get(ui::ui_root))
        // Agent challenge & registration
        .route("/api/v1/agents/challenge", get(agents::agent_challenge))
        .route("/api/v1/agents/register", post(agents::agent_register))
        // Agent CRUD
        .route("/api/v1/agents", get(agents::list_agents))
        .route("/api/v1/agents/{id}", get(agents::get_agent))
        .route("/api/v1/agents/{id}", delete(agents::delete_agent))
        .route("/api/v1/agents/{id}/reset", post(agents::reset_agent))
        // Agent heartbeat & checks
        .route(
            "/api/v1/agents/{id}/heartbeat",
            post(agents::agent_heartbeat),
        )
        .route(
            "/api/v1/agents/{id}/deployment",
            get(deployments::get_agent_deployment),
        )
        .route(
            "/api/v1/agents/{id}/deploy",
            post(deployments::deploy_to_agent),
        )
        .route(
            "/api/v1/agents/{id}/deployment/{deployment_id}/status",
            post(deployments::update_agent_deployment_status),
        )
        .route("/api/v1/agents/{id}/checks", post(agents::ingest_check))
        .route("/api/v1/agents/{id}/checks", get(agents::list_checks))
        // Deployments
        .route("/api/v1/deployments", get(deployments::list_deployments))
        .route("/api/v1/deployments/{id}", get(deployments::get_deployment))
        // Control plane self-attestation
        .route("/api/v1/attestation", get(attestation::get_attestation))
        // Stats
        .route("/api/v1/stats/apps", get(stats::app_stats))
        .route("/api/v1/stats/agents", get(stats::agent_stats))
        // Accounts
        .route("/api/v1/accounts", post(accounts::create_account))
        .route("/api/v1/accounts", get(accounts::list_accounts))
        // Admin
        .route("/api/v1/admin/measurements", get(admin::list_measurements))
        .route("/api/v1/admin/measurements", post(admin::add_measurement))
        // Auth
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/me", get(auth::me))
        .with_state(state)
}
