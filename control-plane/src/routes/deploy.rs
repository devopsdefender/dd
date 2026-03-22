use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::api::{DeployRequest, DeployResponse};
use crate::common::error::AppError;
use crate::state::AppState;
use crate::stores::{agent as agent_store, deployment as deployment_store};
use crate::types::DeploymentStatus;

/// POST /api/v1/deploy
pub async fn deploy(
    State(state): State<AppState>,
    Json(req): Json<DeployRequest>,
) -> Result<(StatusCode, Json<DeployResponse>), AppError> {
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

    // Create deployment record
    let deployment_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    let dep = deployment_store::DeploymentRow {
        id: deployment_id.to_string(),
        agent_id: agent.id.clone(),
        app_name: req.app_name,
        app_version: req.app_version,
        compose: req.compose,
        config: req.config,
        status: "deploying".into(),
        created_at: now.clone(),
        updated_at: now,
    };
    deployment_store::insert_deployment(&state.db, &dep)?;

    // Update agent status
    agent_store::update_agent_status(&state.db, &agent.id, "deploying")?;

    Ok((
        StatusCode::CREATED,
        Json(DeployResponse {
            deployment_id,
            agent_id,
            status: DeploymentStatus::Deploying,
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

    #[tokio::test]
    async fn deploy_no_agents_returns_not_found() {
        let state = test_state();
        let app = build_router(state);

        let deploy_req = DeployRequest {
            compose: "version: '3'".into(),
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
}
