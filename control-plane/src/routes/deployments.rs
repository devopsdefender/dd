use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;

use crate::api::{
    AgentDeployRequest, AgentDeployResponse, AgentDeploymentResponse, AgentDeploymentStatusRequest,
};
use crate::auth::admin_session;
use crate::common::error::AppError;
use crate::state::AppState;
use crate::stores::{
    agent as agent_store, deployment as deployment_store, session as session_store,
};
use crate::types::{AgentStatus, DeploymentStatus};

/// POST /api/v1/agents/{id}/deploy
pub async fn deploy_to_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<AgentDeployRequest>,
) -> Result<(StatusCode, Json<AgentDeployResponse>), AppError> {
    require_admin_session(&state, &headers)?;

    let agent = agent_store::get_agent(&state.db, &agent_id)?.ok_or(AppError::NotFound)?;
    if agent.deployment_id.is_some() || agent.status != AgentStatus::Undeployed.to_string() {
        return Err(AppError::Conflict(
            "agent already has an active deployment".into(),
        ));
    }
    if req.image.trim().is_empty() {
        return Err(AppError::InvalidInput(
            "deployment image is required".into(),
        ));
    }

    let deployment_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    let dep = deployment_store::DeploymentRow {
        id: deployment_id.to_string(),
        agent_id: agent_id.clone(),
        image: req.image,
        env: req.env,
        cmd: req.cmd,
        status: DeploymentStatus::Deploying.to_string(),
        created_at: now.clone(),
        updated_at: now,
    };
    deployment_store::insert_deployment(&state.db, &dep)?;
    agent_store::update_agent_deployment(&state.db, &agent_id, Some(&dep.id))?;
    agent_store::update_agent_status(&state.db, &agent_id, &AgentStatus::Deploying.to_string())?;

    Ok((
        StatusCode::CREATED,
        Json(AgentDeployResponse {
            deployment_id,
            agent_id: agent_id.parse().map_err(|_| AppError::Internal)?,
            status: DeploymentStatus::Deploying,
        }),
    ))
}

/// GET /api/v1/agents/{id}/deployment
pub async fn get_agent_deployment(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<StatusCodeOrJson<AgentDeploymentResponse>, AppError> {
    let agent = agent_store::get_agent(&state.db, &agent_id)?.ok_or(AppError::NotFound)?;
    let Some(deployment_id) = agent.deployment_id else {
        return Ok(StatusCodeOrJson::Status(StatusCode::NO_CONTENT));
    };

    let dep =
        deployment_store::get_deployment(&state.db, &deployment_id)?.ok_or(AppError::NotFound)?;
    Ok(StatusCodeOrJson::Json(Json(AgentDeploymentResponse {
        image: dep.image,
        env: dep.env,
        cmd: dep.cmd,
        deployment_id: dep.id.parse().map_err(|_| AppError::Internal)?,
    })))
}

/// POST /api/v1/agents/{id}/deployment/{deployment_id}/status
pub async fn update_agent_deployment_status(
    State(state): State<AppState>,
    Path((agent_id, deployment_id)): Path<(String, String)>,
    Json(req): Json<AgentDeploymentStatusRequest>,
) -> Result<StatusCode, AppError> {
    let agent = agent_store::get_agent(&state.db, &agent_id)?.ok_or(AppError::NotFound)?;
    if agent.deployment_id.as_deref() != Some(deployment_id.as_str()) {
        return Err(AppError::NotFound);
    }

    let deployment =
        deployment_store::get_deployment(&state.db, &deployment_id)?.ok_or(AppError::NotFound)?;
    if deployment.agent_id != agent_id {
        return Err(AppError::NotFound);
    }

    match req.status.as_str() {
        "running" => {
            deployment_store::update_deployment_status(
                &state.db,
                &deployment_id,
                &DeploymentStatus::Running.to_string(),
            )?;
            agent_store::update_agent_status(
                &state.db,
                &agent_id,
                &AgentStatus::Deployed.to_string(),
            )?;
        }
        "stopped" | "failed" => {
            let deployment_status = if req.status == "stopped" {
                DeploymentStatus::Stopped
            } else {
                DeploymentStatus::Failed
            };
            deployment_store::update_deployment_status(
                &state.db,
                &deployment_id,
                &deployment_status.to_string(),
            )?;
            agent_store::update_agent_deployment(&state.db, &agent_id, None)?;
            agent_store::update_agent_status(
                &state.db,
                &agent_id,
                &AgentStatus::Undeployed.to_string(),
            )?;
        }
        other => {
            return Err(AppError::InvalidInput(format!(
                "unsupported deployment status {other:?}"
            )));
        }
    }

    Ok(StatusCode::OK)
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

fn require_admin_session(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let auth_value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let token = auth_value
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized)?;
    let prefix = admin_session::token_prefix_from_raw(token);
    let session =
        session_store::find_by_prefix(&state.db, &prefix)?.ok_or(AppError::Unauthorized)?;

    if !admin_session::verify_session_token(token, &session.token_hash) {
        return Err(AppError::Unauthorized);
    }

    let expires_at = chrono::DateTime::parse_from_rfc3339(&session.expires_at)
        .map_err(|_| AppError::Internal)?;
    if expires_at < chrono::Utc::now().fixed_offset() {
        return Err(AppError::Unauthorized);
    }

    Ok(())
}

pub enum StatusCodeOrJson<T> {
    Status(StatusCode),
    Json(Json<T>),
}

impl<T> axum::response::IntoResponse for StatusCodeOrJson<T>
where
    Json<T>: axum::response::IntoResponse,
{
    fn into_response(self) -> axum::response::Response {
        match self {
            StatusCodeOrJson::Status(status) => status.into_response(),
            StatusCodeOrJson::Json(json) => json.into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::admin_session;
    use crate::db;
    use crate::routes::build_router;
    use crate::stores::{agent as agent_store, session as session_store};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let db = db::connect_and_migrate("sqlite://:memory:").unwrap();
        AppState::for_testing(db)
    }

    fn insert_agent(state: &AppState, id: &str) {
        let agent = agent_store::AgentRow {
            id: id.into(),
            vm_name: format!("vm-{id}"),
            status: AgentStatus::Undeployed.to_string(),
            registration_state: "ready".into(),
            hostname: None,
            tunnel_id: None,
            mrtd: None,
            tcb_status: None,
            node_size: None,
            datacenter: None,
            github_owner: None,
            deployment_id: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            last_heartbeat_at: None,
        };
        agent_store::insert_agent(&state.db, &agent).unwrap();
    }

    fn admin_header(state: &AppState) -> String {
        let raw = admin_session::issue_session_token();
        let session = session_store::SessionRow {
            id: uuid::Uuid::new_v4().to_string(),
            token_hash: admin_session::hash_session_token(&raw),
            token_prefix: admin_session::token_prefix_from_raw(&raw),
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        };
        session_store::insert_session(&state.db, &session).unwrap();
        format!("Bearer {raw}")
    }

    #[tokio::test]
    async fn deploy_and_fetch_agent_deployment() {
        let state = test_state();
        insert_agent(&state, "11111111-1111-1111-1111-111111111111");
        let auth_header = admin_header(&state);
        let app = build_router(state.clone());

        let deploy_req = AgentDeployRequest {
            image: "ghcr.io/devopsdefender/workload:latest".into(),
            env: vec!["KEY=VALUE".into()],
            cmd: vec![],
        };

        let req = Request::builder()
            .uri("/api/v1/agents/11111111-1111-1111-1111-111111111111/deploy")
            .method("POST")
            .header("content-type", "application/json")
            .header("authorization", auth_header)
            .body(Body::from(serde_json::to_string(&deploy_req).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = Request::builder()
            .uri("/api/v1/agents/11111111-1111-1111-1111-111111111111/deployment")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn deployment_poll_returns_no_content_when_unassigned() {
        let state = test_state();
        insert_agent(&state, "11111111-1111-1111-1111-111111111111");
        let app = build_router(state);

        let req = Request::builder()
            .uri("/api/v1/agents/11111111-1111-1111-1111-111111111111/deployment")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
