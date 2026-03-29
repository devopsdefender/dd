pub mod accounts;
pub mod admin;
pub mod agents;
pub mod apps;
pub mod auth;
pub mod deploy;
pub mod health;
pub mod providers;
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
        // Agent CRUD
        .route("/api/v1/agents", get(agents::list_agents))
        .route("/api/v1/agents/{id}", get(agents::get_agent))
        .route("/api/v1/agents/{id}", delete(agents::delete_agent))
        .route("/api/v1/agents/{id}/reset", post(agents::reset_agent))
        .route("/api/v1/agents/{id}/quote", get(agents::get_agent_quote))
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
        // Auth
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/me", get(auth::me))
        // App catalog
        .route("/api/v1/apps", get(apps::list_apps))
        .route("/api/v1/apps", post(apps::create_app))
        .route("/api/v1/apps/{id}", get(apps::get_app))
        .route("/api/v1/apps/{id}", delete(apps::delete_app))
        .route("/api/v1/apps/{id}/versions", get(apps::list_versions))
        .route("/api/v1/apps/{id}/versions", post(apps::create_version))
        // App deploy grants
        .route("/api/v1/apps/{id}/deployers", get(apps::list_deployers))
        .route("/api/v1/apps/{id}/deployers", post(apps::grant_deploy))
        .route(
            "/api/v1/apps/{app_id}/deployers/{account_id}",
            delete(apps::revoke_deploy),
        )
        // Providers
        .route("/api/v1/providers", get(providers::list_providers))
        .route("/api/v1/providers", post(providers::register_provider))
        .route("/api/v1/providers/{id}", delete(providers::revoke_provider))
        // Provider SKUs
        .route(
            "/api/v1/providers/{id}/skus",
            get(providers::list_provider_skus),
        )
        .route("/api/v1/providers/{id}/skus", post(providers::register_sku))
        .route("/api/v1/skus", get(providers::list_all_skus))
        // Measurements (app)
        .route(
            "/api/v1/apps/{app_id}/versions/{version_id}/measure",
            post(providers::submit_app_measurement),
        )
        .route(
            "/api/v1/apps/{app_id}/versions/{version_id}/measurements",
            get(providers::list_app_measurements),
        )
        // Measurements (node)
        .route(
            "/api/v1/agents/{id}/measure",
            post(providers::submit_node_measurement),
        )
        .route(
            "/api/v1/agents/{id}/measurements",
            get(providers::list_node_measurements),
        )
        .with_state(state)
}
