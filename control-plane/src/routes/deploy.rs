use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::api::{DeployRequest, DeployResponse, UpdateDeploymentStatusRequest};
use crate::common::error::AppError;
use crate::state::AppState;
use crate::stores::{agent as agent_store, deployment as deployment_store};
use crate::types::DeploymentStatus;

/// POST /api/v1/deploy
pub async fn deploy(
    State(state): State<AppState>,
    Json(req): Json<DeployRequest>,
) -> Result<(StatusCode, Json<DeployResponse>), AppError> {
    // Validate: exactly one of compose or image must be set
    if req.compose.is_none() && req.image.is_none() {
        return Err(AppError::InvalidInput(
            "exactly one of 'compose' or 'image' must be provided".into(),
        ));
    }
    if req.compose.is_some() && req.image.is_some() {
        return Err(AppError::InvalidInput(
            "cannot set both 'compose' and 'image'".into(),
        ));
    }

    // Find an available agent
    let agent = agent_store::find_available_agent(
        &state.db,
        req.node_size.as_deref(),
        req.datacenter.as_deref(),
    )?
    .ok_or(AppError::NotFound)?;

    let agent_id: uuid::Uuid = agent.id.parse().map_err(|_| AppError::Internal)?;

    let dry_run = req.dry_run.unwrap_or(false);
    if dry_run {
        return Ok((
            StatusCode::OK,
            Json(DeployResponse {
                deployment_id: uuid::Uuid::new_v4(),
                agent_id,
                status: DeploymentStatus::Pending,
            }),
        ));
    }

    // Serialize list fields as JSON for storage
    let env_json = req
        .env
        .map(|v| serde_json::to_string(&v).unwrap_or_default());
    let cmd_json = req
        .cmd
        .map(|v| serde_json::to_string(&v).unwrap_or_default());
    let ports_json = req
        .ports
        .map(|v| serde_json::to_string(&v).unwrap_or_default());

    // Create deployment record as pending -- agent picks it up via heartbeat
    let deployment_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    let dep = deployment_store::DeploymentRow {
        id: deployment_id.to_string(),
        agent_id: agent.id.clone(),
        app_name: req.app_name,
        app_version: req.app_version,
        compose: req.compose,
        image: req.image,
        env: env_json,
        cmd: cmd_json,
        ports: ports_json,
        config: req.config,
        status: "pending".into(),
        error_message: None,
        previous_deployment_id: None,
        created_at: now.clone(),
        updated_at: now,
    };
    deployment_store::insert_deployment(&state.db, &dep)?;

    Ok((
        StatusCode::CREATED,
        Json(DeployResponse {
            deployment_id,
            agent_id,
            status: DeploymentStatus::Pending,
        }),
    ))
}

#[derive(Debug, serde::Deserialize)]
pub struct DeploymentListQuery {
    pub agent_id: Option<String>,
}

/// GET /api/v1/deployments
pub async fn list_deployments(
    State(state): State<AppState>,
    Query(query): Query<DeploymentListQuery>,
) -> Result<Json<Vec<deployment_store::DeploymentRow>>, AppError> {
    let deps = deployment_store::list_deployments(&state.db, query.agent_id.as_deref())?;
    Ok(Json(deps))
}

/// GET /api/v1/deployments/{id}
pub async fn get_deployment(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<deployment_store::DeploymentRow>, AppError> {
    let dep = deployment_store::get_deployment(&state.db, &id)?.ok_or(AppError::NotFound)?;
    Ok(Json(dep))
}

/// PATCH /api/v1/deployments/{id}/status
/// Agents call this to report deployment status (running, failed, etc.)
pub async fn update_deployment_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateDeploymentStatusRequest>,
) -> Result<Json<deployment_store::DeploymentRow>, AppError> {
    let _dep = deployment_store::get_deployment(&state.db, &id)?.ok_or(AppError::NotFound)?;

    let status_str = req.status.to_string();
    deployment_store::update_deployment_status_with_error(
        &state.db,
        &id,
        &status_str,
        req.error_message.as_deref(),
    )?;

    let updated = deployment_store::get_deployment(&state.db, &id)?.ok_or(AppError::Internal)?;
    Ok(Json(updated))
}

/// POST /api/v1/deployments/{id}/stop
/// Request to stop a running deployment.
pub async fn stop_deployment(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<deployment_store::DeploymentRow>, AppError> {
    let dep = deployment_store::get_deployment(&state.db, &id)?.ok_or(AppError::NotFound)?;

    // Can only stop running or deploying deployments
    if dep.status != "running" && dep.status != "deploying" {
        return Err(AppError::InvalidInput(format!(
            "cannot stop deployment in '{}' status",
            dep.status
        )));
    }

    deployment_store::update_deployment_status(&state.db, &id, "stopped")?;

    let updated = deployment_store::get_deployment(&state.db, &id)?.ok_or(AppError::Internal)?;
    Ok(Json(updated))
}

/// POST /api/v1/deployments/{id}/rollback
/// Create a new deployment from the previous version of this deployment's app.
pub async fn rollback_deployment(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<DeployResponse>), AppError> {
    let dep = deployment_store::get_deployment(&state.db, &id)?.ok_or(AppError::NotFound)?;

    // Find the previous deployment to roll back to
    let prev_id = dep
        .previous_deployment_id
        .as_deref()
        .ok_or_else(|| AppError::InvalidInput("no previous deployment to rollback to".into()))?;

    let prev_dep =
        deployment_store::get_deployment(&state.db, prev_id)?.ok_or(AppError::NotFound)?;

    // Create a new deployment with the previous compose content
    let new_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    let agent_id: uuid::Uuid = dep.agent_id.parse().map_err(|_| AppError::Internal)?;

    let new_dep = deployment_store::DeploymentRow {
        id: new_id.to_string(),
        agent_id: dep.agent_id.clone(),
        app_name: prev_dep.app_name,
        app_version: prev_dep.app_version,
        compose: prev_dep.compose,
        image: prev_dep.image,
        env: prev_dep.env,
        cmd: prev_dep.cmd,
        ports: prev_dep.ports,
        config: prev_dep.config,
        status: "pending".into(),
        error_message: None,
        previous_deployment_id: Some(id),
        created_at: now.clone(),
        updated_at: now,
    };
    deployment_store::insert_deployment(&state.db, &new_dep)?;

    // Stop the current deployment
    if dep.status == "running" || dep.status == "deploying" {
        deployment_store::update_deployment_status(&state.db, &dep.id, "stopped")?;
    }

    Ok((
        StatusCode::CREATED,
        Json(DeployResponse {
            deployment_id: new_id,
            agent_id,
            status: DeploymentStatus::Pending,
        }),
    ))
}

/// GET /api/v1/deployments/{id}/logs
/// Get deployment container logs (stored from agent status updates).
pub async fn get_deployment_logs(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let dep = deployment_store::get_deployment(&state.db, &id)?.ok_or(AppError::NotFound)?;

    Ok(Json(serde_json::json!({
        "deployment_id": dep.id,
        "status": dep.status,
        "error_message": dep.error_message,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::routes::build_router;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let db = db::connect_and_migrate("sqlite://:memory:").unwrap();
        AppState::for_testing(db)
    }

    use crate::stores::agent as agent_store;

    const TEST_AGENT_ID: &str = "00000000-0000-0000-0000-000000000001";

    fn ensure_agent(state: &AppState) {
        let agent = agent_store::AgentRow {
            id: TEST_AGENT_ID.into(),
            vm_name: "vm-test".into(),
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
            last_heartbeat_at: Some(chrono::Utc::now().to_rfc3339()),
            last_attested_at: Some(chrono::Utc::now().to_rfc3339()),
        };
        let _ = agent_store::insert_agent(&state.db, &agent);
    }

    #[tokio::test]
    async fn deploy_no_agents_returns_not_found() {
        let state = test_state();
        let app = build_router(state);

        let deploy_req = DeployRequest {
            compose: Some("version: '3'".into()),
            image: None,
            env: None,
            cmd: None,
            ports: None,
            config: None,
            app_name: None,
            app_version: None,
            agent_name: None,
            node_size: None,
            datacenter: None,
            dry_run: None,
        };

        let req = Request::builder()
            .uri("/api/v1/deploy")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&deploy_req).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn deploy_creates_pending_deployment() {
        let state = test_state();
        ensure_agent(&state);
        let app = build_router(state.clone());

        let deploy_req = DeployRequest {
            compose: Some("version: '3'\nservices:\n  web:\n    image: nginx".into()),
            image: None,
            env: None,
            cmd: None,
            ports: None,
            config: None,
            app_name: Some("test-app".into()),
            app_version: Some("1.0".into()),
            agent_name: None,
            node_size: None,
            datacenter: None,
            dry_run: None,
        };

        let req = Request::builder()
            .uri("/api/v1/deploy")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&deploy_req).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let deploy_resp: DeployResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(deploy_resp.status, DeploymentStatus::Pending);

        // Verify the deployment is in pending status in DB
        let dep =
            deployment_store::get_deployment(&state.db, &deploy_resp.deployment_id.to_string())
                .unwrap()
                .unwrap();
        assert_eq!(dep.status, "pending");
    }

    #[tokio::test]
    async fn multiple_deploys_to_same_agent() {
        let state = test_state();
        ensure_agent(&state);

        // Deploy first app
        let app1 = build_router(state.clone());
        let req1 = Request::builder()
            .uri("/api/v1/deploy")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&DeployRequest {
                    compose: Some("version: '3'\nservices:\n  app1:\n    image: nginx".into()),
                    image: None,
                    env: None,
                    cmd: None,
                    ports: None,
                    config: None,
                    app_name: Some("app1".into()),
                    app_version: None,
                    agent_name: None,
                    node_size: None,
                    datacenter: None,
                    dry_run: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let resp1 = app1.oneshot(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::CREATED);

        // Deploy second app to same agent -- should succeed (multi-deployment)
        let app2 = build_router(state.clone());
        let req2 = Request::builder()
            .uri("/api/v1/deploy")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&DeployRequest {
                    compose: Some("version: '3'\nservices:\n  app2:\n    image: redis".into()),
                    image: None,
                    env: None,
                    cmd: None,
                    ports: None,
                    config: None,
                    app_name: Some("app2".into()),
                    app_version: None,
                    agent_name: None,
                    node_size: None,
                    datacenter: None,
                    dry_run: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let resp2 = app2.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::CREATED);

        // Verify both deployments exist
        let deps = deployment_store::list_deployments(&state.db, Some(TEST_AGENT_ID)).unwrap();
        assert_eq!(deps.len(), 2);
    }

    #[tokio::test]
    async fn heartbeat_returns_pending_deployments() {
        let state = test_state();
        ensure_agent(&state);

        // Create a pending deployment
        let now = chrono::Utc::now().to_rfc3339();
        let dep = deployment_store::DeploymentRow {
            id: "dep-1".into(),
            agent_id: TEST_AGENT_ID.into(),
            app_name: Some("test-app".into()),
            app_version: Some("1.0".into()),
            compose: Some("version: '3'".into()),
            image: None,
            env: None,
            cmd: None,
            ports: None,
            config: None,
            status: "pending".into(),
            error_message: None,
            previous_deployment_id: None,
            created_at: now.clone(),
            updated_at: now,
        };
        deployment_store::insert_deployment(&state.db, &dep).unwrap();

        // Heartbeat should return the pending deployment
        let app = build_router(state.clone());
        let req = Request::builder()
            .uri(format!("/api/v1/agents/{}/heartbeat", TEST_AGENT_ID))
            .method("POST")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let hb: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(hb["ok"], true);
        let pending = hb["pending_deployments"].as_array().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["id"], "dep-1");

        // After heartbeat, deployment should be marked as deploying
        let dep = deployment_store::get_deployment(&state.db, "dep-1")
            .unwrap()
            .unwrap();
        assert_eq!(dep.status, "deploying");

        // Second heartbeat should return no pending deployments
        let app2 = build_router(state.clone());
        let req2 = Request::builder()
            .uri(format!("/api/v1/agents/{}/heartbeat", TEST_AGENT_ID))
            .method("POST")
            .body(Body::empty())
            .unwrap();
        let resp2 = app2.oneshot(req2).await.unwrap();
        let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let hb2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
        assert!(hb2["pending_deployments"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_deployment_status_endpoint() {
        let state = test_state();
        ensure_agent(&state);

        let now = chrono::Utc::now().to_rfc3339();
        let dep = deployment_store::DeploymentRow {
            id: "dep-status".into(),
            agent_id: TEST_AGENT_ID.into(),
            app_name: None,
            app_version: None,
            compose: Some("version: '3'".into()),
            image: None,
            env: None,
            cmd: None,
            ports: None,
            config: None,
            status: "deploying".into(),
            error_message: None,
            previous_deployment_id: None,
            created_at: now.clone(),
            updated_at: now,
        };
        deployment_store::insert_deployment(&state.db, &dep).unwrap();

        let app = build_router(state.clone());
        let req = Request::builder()
            .uri("/api/v1/deployments/dep-status/status")
            .method("PATCH")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"status":"running"}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let updated = deployment_store::get_deployment(&state.db, "dep-status")
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, "running");
    }

    #[tokio::test]
    async fn stop_deployment_endpoint() {
        let state = test_state();
        ensure_agent(&state);

        let now = chrono::Utc::now().to_rfc3339();
        let dep = deployment_store::DeploymentRow {
            id: "dep-stop".into(),
            agent_id: TEST_AGENT_ID.into(),
            app_name: None,
            app_version: None,
            compose: Some("version: '3'".into()),
            image: None,
            env: None,
            cmd: None,
            ports: None,
            config: None,
            status: "running".into(),
            error_message: None,
            previous_deployment_id: None,
            created_at: now.clone(),
            updated_at: now,
        };
        deployment_store::insert_deployment(&state.db, &dep).unwrap();

        let app = build_router(state.clone());
        let req = Request::builder()
            .uri("/api/v1/deployments/dep-stop/stop")
            .method("POST")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let updated = deployment_store::get_deployment(&state.db, "dep-stop")
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, "stopped");
    }
}
