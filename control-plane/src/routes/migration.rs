use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::api::{
    AgentReattachRequest, BootstrapDeployCpRequest, BootstrapDeployCpResponse,
    MigrationImportResponse, MigrationReadinessResponse, MigrationStatusResponse,
    ProxyStartRequest,
};
use crate::common::error::AppError;
use crate::services::migration::{SeedConfig, StateBundle};
use crate::state::AppState;
use crate::stores::{agent as agent_store, deployment as deployment_store};
use crate::types::DeploymentStatus;

// ── Status & readiness ──────────────────────────────────────────────────────

/// GET /api/v1/admin/migration/status
pub async fn migration_status(
    State(state): State<AppState>,
) -> Result<Json<MigrationStatusResponse>, AppError> {
    let agents = agent_store::list_agents(&state.db)?;
    let deployments = deployment_store::list_deployments(&state.db, None)?;
    let proxy = state.proxy_target.read().unwrap().clone();

    Ok(Json(MigrationStatusResponse {
        cp_mode: state.cp_mode.clone(),
        can_export: true,
        can_import: true,
        agent_count: agents.len(),
        deployment_count: deployments.len(),
        proxy_target: proxy,
    }))
}

/// GET /api/v1/admin/migration/readiness
/// Check if the new CP has all expected agents re-registered.
pub async fn migration_readiness(
    State(state): State<AppState>,
) -> Result<Json<MigrationReadinessResponse>, AppError> {
    let expected = state.expected_agent_count.read().unwrap().unwrap_or(0);
    let current_agents = agent_store::list_agents(&state.db)?;
    let registered = current_agents.len();

    // If we don't know the expected count yet, report not ready
    if expected == 0 {
        return Ok(Json(MigrationReadinessResponse {
            ready: false,
            agents_registered: registered,
            agents_expected: 0,
            agents_missing: vec![],
        }));
    }

    Ok(Json(MigrationReadinessResponse {
        ready: registered >= expected,
        agents_registered: registered,
        agents_expected: expected,
        agents_missing: vec![], // Can't list specifics without old CP data
    }))
}

// ── Export ───────────────────────────────────────────────────────────────────

/// POST /api/v1/admin/migration/export/seed
/// Export lightweight seed config (accounts, settings, trusted_mrtds, apps).
/// Agents and deployments are NOT included — they re-register naturally.
pub async fn export_seed(State(state): State<AppState>) -> Result<Json<SeedConfig>, AppError> {
    let seed = SeedConfig::export(&state.db, &state.git_sha)?;
    Ok(Json(seed))
}

/// POST /api/v1/admin/migration/export/full
/// Export full state bundle including all agents and deployments.
/// Use this for instant cutover when you can't wait for re-registration.
pub async fn export_full(State(state): State<AppState>) -> Result<Json<StateBundle>, AppError> {
    let bundle = StateBundle::export(&state.db, &state.git_sha)?;
    Ok(Json(bundle))
}

// ── Import ──────────────────────────────────────────────────────────────────

/// POST /api/v1/admin/migration/import/seed
/// Import seed config into this CP.
pub async fn import_seed(
    State(state): State<AppState>,
    Json(seed): Json<SeedConfig>,
) -> Result<Json<MigrationImportResponse>, AppError> {
    let summary = seed.summary();
    seed.import(&state.db)?;

    Ok(Json(MigrationImportResponse {
        imported: true,
        summary,
    }))
}

/// POST /api/v1/admin/migration/import/full
/// Import full state bundle (instant cutover).
pub async fn import_full(
    State(state): State<AppState>,
    Json(bundle): Json<StateBundle>,
) -> Result<Json<MigrationImportResponse>, AppError> {
    let seed_summary = {
        // Extract just the seed table counts for the summary
        let mut table_counts = std::collections::HashMap::new();
        for (table, rows) in &bundle.database {
            if let Some(arr) = rows.as_array() {
                table_counts.insert(table.clone(), arr.len());
            }
        }
        crate::services::migration::SeedConfigSummary {
            version: bundle.version,
            exported_at: bundle.exported_at.clone(),
            git_sha: bundle.git_sha.clone(),
            table_counts,
        }
    };

    bundle.apply_secrets_to_env();
    bundle.import(&state.db)?;

    Ok(Json(MigrationImportResponse {
        imported: true,
        summary: seed_summary,
    }))
}

// ── Proxy (zero-downtime) ───────────────────────────────────────────────────

/// POST /api/v1/admin/migration/proxy/start
/// Start proxying all requests to the new CP.  The old CP becomes a thin
/// reverse proxy so clients see zero downtime while DNS/tunnels converge.
pub async fn proxy_start(
    State(state): State<AppState>,
    Json(req): Json<ProxyStartRequest>,
) -> Result<StatusCode, AppError> {
    // Record agent count so the new CP can track readiness
    let agents = agent_store::list_agents(&state.db)?;
    *state.expected_agent_count.write().unwrap() = Some(agents.len());

    // Activate proxy
    *state.proxy_target.write().unwrap() = Some(req.target_url.clone());

    eprintln!(
        "migration: proxying traffic to {} ({} agents expected to re-register)",
        req.target_url,
        agents.len()
    );

    Ok(StatusCode::OK)
}

/// POST /api/v1/admin/migration/proxy/stop
/// Stop proxying and resume local handling.
pub async fn proxy_stop(State(state): State<AppState>) -> Result<StatusCode, AppError> {
    *state.proxy_target.write().unwrap() = None;
    eprintln!("migration: proxy stopped, handling traffic locally");
    Ok(StatusCode::OK)
}

// ── Agent reattach ──────────────────────────────────────────────────────────

/// POST /api/v1/agents/reattach
/// Called by an agent that heartbeated a new CP and got 404.
/// Creates the agent record and restores its running deployments.
pub async fn agent_reattach(
    State(state): State<AppState>,
    Json(req): Json<AgentReattachRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let agent_id = uuid::Uuid::new_v4();

    // Create tunnel for the reattaching agent
    let tunnel_info = state
        .tunnel
        .create_tunnel_for_agent(agent_id, &req.vm_name)
        .await?;

    let agent = agent_store::AgentRow {
        id: agent_id.to_string(),
        vm_name: req.vm_name.clone(),
        status: if req.running_deployments.is_empty() {
            "undeployed".into()
        } else {
            "deployed".into()
        },
        registration_state: "ready".into(),
        hostname: Some(tunnel_info.hostname.clone()),
        tunnel_id: Some(tunnel_info.tunnel_id),
        mrtd: None,
        tcb_status: None,
        node_size: req.node_size,
        datacenter: req.datacenter,
        github_owner: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        last_heartbeat_at: Some(chrono::Utc::now().to_rfc3339()),
    };
    agent_store::insert_agent(&state.db, &agent)?;

    // Restore running deployment records
    for dep in &req.running_deployments {
        let now = chrono::Utc::now().to_rfc3339();
        let row = deployment_store::DeploymentRow {
            id: dep.deployment_id.clone(),
            agent_id: agent_id.to_string(),
            app_name: dep.app_name.clone(),
            app_version: None,
            compose: None,
            image: dep.image.clone(),
            env: None,
            cmd: None,
            ports: None,
            config: None,
            status: dep.status.clone(),
            error_message: None,
            previous_deployment_id: None,
            created_at: now.clone(),
            updated_at: now,
        };
        // Ignore duplicate errors — deployment might already exist from seed import
        let _ = deployment_store::insert_deployment(&state.db, &row);
    }

    eprintln!(
        "migration: agent {} reattached as {} with {} deployments",
        req.vm_name,
        agent_id,
        req.running_deployments.len()
    );

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "agent_id": agent_id,
            "tunnel_token": tunnel_info.tunnel_token,
            "hostname": tunnel_info.hostname,
        })),
    ))
}

// ── Bootstrap: deploy portable CP ───────────────────────────────────────────

/// POST /api/v1/admin/migration/deploy-cp
/// Bootstrap-only: deploy the portable CP as a container workload on an agent.
/// Exports the seed config and passes secrets as container env vars.
/// Agents will naturally re-register with the new CP.
pub async fn bootstrap_deploy_cp(
    State(state): State<AppState>,
    Json(req): Json<BootstrapDeployCpRequest>,
) -> Result<(StatusCode, Json<BootstrapDeployCpResponse>), AppError> {
    if state.cp_mode != "bootstrap" {
        return Err(AppError::InvalidInput(
            "deploy-cp is only available in bootstrap mode".into(),
        ));
    }

    // Find or validate the target agent
    let agent = if let Some(ref agent_id) = req.agent_id {
        agent_store::get_agent(&state.db, agent_id)?.ok_or(AppError::NotFound)?
    } else {
        agent_store::find_available_agent(
            &state.db,
            req.node_size.as_deref(),
            req.datacenter.as_deref(),
        )?
        .ok_or(AppError::NotFound)?
    };

    let agent_id: uuid::Uuid = agent.id.parse().map_err(|_| AppError::Internal)?;

    // Export seed config for the new CP
    let seed = SeedConfig::export(&state.db, &state.git_sha)?;
    let seed_json = serde_json::to_string(&seed)
        .map_err(|e| AppError::External(format!("serialize seed: {e}")))?;

    // Build env vars: secrets + mode + seed config inline
    let mut env_vars = vec![
        "DD_CP_MODE=portable".to_string(),
        "DD_CP_BIND_ADDR=0.0.0.0:8080".to_string(),
    ];

    // Collect current secrets from env
    for &key in crate::services::migration::SECRET_ENV_VARS {
        if let Ok(val) = std::env::var(key) {
            env_vars.push(format!("{key}={val}"));
        }
    }

    // Pass seed config inline so the new CP imports it on startup
    env_vars.push(format!("DD_CP_IMPORT_SEED_INLINE={seed_json}"));

    let env_json = serde_json::to_string(&env_vars).unwrap_or_default();

    let deployment_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    let dep = deployment_store::DeploymentRow {
        id: deployment_id.to_string(),
        agent_id: agent.id.clone(),
        app_name: Some("devopsdefender-cp".into()),
        app_version: Some(state.git_sha.clone()),
        compose: None,
        image: Some(req.image),
        env: Some(env_json),
        cmd: None,
        ports: Some(serde_json::to_string(&vec!["8080:8080"]).unwrap_or_default()),
        config: None,
        status: "pending".into(),
        error_message: None,
        previous_deployment_id: None,
        created_at: now.clone(),
        updated_at: now,
    };
    deployment_store::insert_deployment(&state.db, &dep)?;

    Ok((
        StatusCode::CREATED,
        Json(BootstrapDeployCpResponse {
            deployment_id,
            agent_id,
            status: DeploymentStatus::Pending,
            seed_config_included: true,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::RunningDeploymentReport;
    use crate::db;
    use crate::routes::build_router;
    use crate::stores::agent as agent_store;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let db = db::connect_and_migrate("sqlite://:memory:").unwrap();
        AppState::for_testing(db)
    }

    #[tokio::test]
    async fn migration_status_returns_info() {
        let state = test_state();
        let app = build_router(state);

        let req = Request::builder()
            .uri("/api/v1/admin/migration/status")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: MigrationStatusResponse = serde_json::from_slice(&body).unwrap();
        assert!(status.can_export);
        assert_eq!(status.agent_count, 0);
        assert!(status.proxy_target.is_none());
    }

    #[tokio::test]
    async fn export_seed_excludes_agents() {
        let state = test_state();

        // Insert an agent and a setting
        let agent = agent_store::AgentRow {
            id: "test-agent-1".into(),
            vm_name: "vm-export-test".into(),
            status: "undeployed".into(),
            registration_state: "ready".into(),
            hostname: Some("test.devopsdefender.com".into()),
            tunnel_id: None,
            mrtd: None,
            tcb_status: None,
            node_size: None,
            datacenter: None,
            github_owner: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            last_heartbeat_at: None,
        };
        agent_store::insert_agent(&state.db, &agent).unwrap();
        state.settings.set("test-key", "test-val").unwrap();

        let app = build_router(state);

        let req = Request::builder()
            .uri("/api/v1/admin/migration/export/seed")
            .method("POST")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let seed: SeedConfig = serde_json::from_slice(&body).unwrap();

        // Settings should be included
        let settings = seed.tables.get("settings").unwrap().as_array().unwrap();
        assert_eq!(settings.len(), 1);

        // Agents should NOT be in seed config
        assert!(!seed.tables.contains_key("agents"));
    }

    #[tokio::test]
    async fn agent_reattach_creates_agent_and_deployments() {
        let state = test_state();
        let app = build_router(state.clone());

        let reattach_req = AgentReattachRequest {
            vm_name: "vm-returning".into(),
            node_size: Some("large".into()),
            datacenter: Some("us-central1".into()),
            running_deployments: vec![RunningDeploymentReport {
                deployment_id: "dep-123".into(),
                app_name: Some("my-app".into()),
                image: Some("nginx:latest".into()),
                status: "running".into(),
            }],
        };

        let req = Request::builder()
            .uri("/api/v1/agents/reattach")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&reattach_req).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Verify agent was created
        let agents = agent_store::list_agents(&state.db).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].vm_name, "vm-returning");
        assert_eq!(agents[0].status, "deployed");

        // Verify deployment was recorded
        let deps = deployment_store::list_deployments(&state.db, Some(&agents[0].id)).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].id, "dep-123");
        assert_eq!(deps[0].status, "running");
    }

    #[tokio::test]
    async fn readiness_tracks_expected_count() {
        let state = test_state();

        // Set expected count
        *state.expected_agent_count.write().unwrap() = Some(3);

        // Add 2 agents (not yet at 3)
        for i in 0..2 {
            let agent = agent_store::AgentRow {
                id: format!("agent-{i}"),
                vm_name: format!("vm-{i}"),
                status: "undeployed".into(),
                registration_state: "ready".into(),
                hostname: None,
                tunnel_id: None,
                mrtd: None,
                tcb_status: None,
                node_size: None,
                datacenter: None,
                github_owner: None,
                created_at: chrono::Utc::now().to_rfc3339(),
                last_heartbeat_at: None,
            };
            agent_store::insert_agent(&state.db, &agent).unwrap();
        }

        let app = build_router(state);
        let req = Request::builder()
            .uri("/api/v1/admin/migration/readiness")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let readiness: MigrationReadinessResponse = serde_json::from_slice(&body).unwrap();
        assert!(!readiness.ready);
        assert_eq!(readiness.agents_registered, 2);
        assert_eq!(readiness.agents_expected, 3);
    }
}
