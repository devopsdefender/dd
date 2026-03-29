pub mod accounts;
pub mod admin;
pub mod agents;
pub mod auth;
pub mod deploy;
pub mod health;
pub mod migration;
pub mod stats;
pub mod ui;

use axum::routing::{delete, get, patch, post};
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
        // Agent reattach (migration: re-register with new CP)
        .route("/api/v1/agents/reattach", post(migration::agent_reattach))
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
        .route("/api/v1/agents/{id}/checks", post(agents::ingest_check))
        .route("/api/v1/agents/{id}/checks", get(agents::list_checks))
        // Deploy
        .route("/api/v1/deploy", post(deploy::deploy))
        .route("/api/v1/deployments", get(deploy::list_deployments))
        .route("/api/v1/deployments/{id}", get(deploy::get_deployment))
        .route(
            "/api/v1/deployments/{id}/status",
            patch(deploy::update_deployment_status),
        )
        .route(
            "/api/v1/deployments/{id}/stop",
            post(deploy::stop_deployment),
        )
        .route(
            "/api/v1/deployments/{id}/rollback",
            post(deploy::rollback_deployment),
        )
        .route(
            "/api/v1/deployments/{id}/logs",
            get(deploy::get_deployment_logs),
        )
        // Stats
        .route("/api/v1/stats/apps", get(stats::app_stats))
        .route("/api/v1/stats/agents", get(stats::agent_stats))
        // Accounts
        .route("/api/v1/accounts", post(accounts::create_account))
        .route("/api/v1/accounts", get(accounts::list_accounts))
        // Admin
        .route("/api/v1/admin/measurements", get(admin::list_measurements))
        .route("/api/v1/admin/measurements", post(admin::add_measurement))
        // Migration
        .route(
            "/api/v1/admin/migration/status",
            get(migration::migration_status),
        )
        .route(
            "/api/v1/admin/migration/readiness",
            get(migration::migration_readiness),
        )
        .route(
            "/api/v1/admin/migration/export/seed",
            post(migration::export_seed),
        )
        .route(
            "/api/v1/admin/migration/export/full",
            post(migration::export_full),
        )
        .route(
            "/api/v1/admin/migration/import/seed",
            post(migration::import_seed),
        )
        .route(
            "/api/v1/admin/migration/import/full",
            post(migration::import_full),
        )
        .route(
            "/api/v1/admin/migration/deploy-cp",
            post(migration::deploy_cp),
        )
        .route(
            "/api/v1/admin/migration/proxy/start",
            post(migration::proxy_start),
        )
        .route(
            "/api/v1/admin/migration/proxy/stop",
            post(migration::proxy_stop),
        )
        // Auth
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/me", get(auth::me))
        .with_state(state)
}
