use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::api::{
    AgentChallengeResponse, AgentCheckIngestRequest, AgentCheckIngestResponse,
    AgentRegisterRequest, AgentRegisterResponse,
};
use crate::common::error::AppError;
use crate::services::nonce::ConsumeResult;
use crate::state::AppState;
use crate::stores::{agent as agent_store, health as health_store};

/// GET /api/v1/agents/challenge
pub async fn agent_challenge(State(state): State<AppState>) -> Json<AgentChallengeResponse> {
    let nonce = state.nonce.issue().await;
    Json(AgentChallengeResponse {
        nonce,
        expires_in_seconds: state.nonce.ttl_seconds(),
    })
}

/// POST /api/v1/agents/register
pub async fn agent_register(
    State(state): State<AppState>,
    Json(req): Json<AgentRegisterRequest>,
) -> Result<(StatusCode, Json<AgentRegisterResponse>), AppError> {
    match state.nonce.consume(&req.nonce).await {
        ConsumeResult::Ok => {}
        ConsumeResult::Missing => {
            return Err(AppError::InvalidInput(
                "registration nonce is missing or already used".into(),
            ));
        }
        ConsumeResult::Expired => {
            return Err(AppError::InvalidInput(
                "registration nonce has expired".into(),
            ));
        }
    }

    // Verify attestation quote.
    let attestation = state
        .attestation
        .verify_registration_token(&req.intel_ta_token, &req.nonce)
        .await?;

    // Re-register: if an agent with the same vm_name already exists, reuse its
    // tunnel and update its record instead of creating a brand-new tunnel every
    // time (avoids Cloudflare rate limits on tunnel creation).
    if let Some(existing) = agent_store::find_agent_by_vm_name(&state.db, &req.vm_name)? {
        let agent_id: uuid::Uuid = existing.id.parse().map_err(|_| AppError::Internal)?;
        let hostname = existing.hostname.unwrap_or_default();
        let tunnel_token = state
            .tunnel
            .get_tunnel_token_for_agent(agent_id, &req.vm_name)
            .await
            .unwrap_or_else(|_| format!("reuse-tunnel-token-{agent_id}"));

        // Reset registration state + heartbeat
        agent_store::update_registration_state(&state.db, &existing.id, "ready")?;
        agent_store::update_heartbeat(&state.db, &existing.id)?;

        return Ok((
            StatusCode::CREATED,
            Json(AgentRegisterResponse {
                agent_id,
                tunnel_token,
                hostname,
            }),
        ));
    }

    // New agent: create tunnel
    let agent_id = uuid::Uuid::new_v4();
    let tunnel_info = state
        .tunnel
        .create_tunnel_for_agent(agent_id, &req.vm_name)
        .await?;

    // Store agent
    let agent = agent_store::AgentRow {
        id: agent_id.to_string(),
        vm_name: req.vm_name.clone(),
        status: "undeployed".into(),
        registration_state: "ready".into(),
        hostname: Some(tunnel_info.hostname.clone()),
        tunnel_id: Some(tunnel_info.tunnel_id),
        mrtd: attestation.mrtd,
        tcb_status: attestation.tcb_status,
        node_size: req.node_size,
        datacenter: req.datacenter,
        github_owner: req.github_owner,
        deployment_id: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        last_heartbeat_at: None,
    };
    agent_store::insert_agent(&state.db, &agent)?;

    Ok((
        StatusCode::CREATED,
        Json(AgentRegisterResponse {
            agent_id,
            tunnel_token: tunnel_info.tunnel_token,
            hostname: tunnel_info.hostname,
        }),
    ))
}

/// GET /api/v1/agents
pub async fn list_agents(
    State(state): State<AppState>,
) -> Result<Json<Vec<agent_store::AgentRow>>, AppError> {
    let agents = agent_store::list_agents(&state.db)?;
    Ok(Json(agents))
}

/// GET /api/v1/agents/{id}
pub async fn get_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<agent_store::AgentRow>, AppError> {
    let agent = agent_store::get_agent(&state.db, &id)?.ok_or(AppError::NotFound)?;
    Ok(Json(agent))
}

/// DELETE /api/v1/agents/{id}
pub async fn delete_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let deleted = agent_store::delete_agent(&state.db, &id)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

/// POST /api/v1/agents/{id}/reset
pub async fn reset_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let exists = agent_store::get_agent(&state.db, &id)?.is_some();
    if !exists {
        return Err(AppError::NotFound);
    }
    agent_store::update_agent_status(&state.db, &id, "undeployed")?;
    agent_store::update_registration_state(&state.db, &id, "pending")?;
    Ok(StatusCode::OK)
}

/// POST /api/v1/agents/{id}/heartbeat
pub async fn agent_heartbeat(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let updated = agent_store::update_heartbeat(&state.db, &id)?;
    if updated {
        Ok(StatusCode::OK)
    } else {
        Err(AppError::NotFound)
    }
}

/// POST /api/v1/agents/{id}/checks
pub async fn ingest_check(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<AgentCheckIngestRequest>,
) -> Result<Json<AgentCheckIngestResponse>, AppError> {
    // Verify agent exists
    let _agent = agent_store::get_agent(&state.db, &id)?.ok_or(AppError::NotFound)?;

    let app_name = req.app_name.clone().unwrap_or_else(|| "default".into());
    let check_ok = req.health_ok && req.attestation_ok;

    // Store the check
    let check = health_store::HealthCheckRow {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: id.clone(),
        app_name: Some(app_name.clone()),
        health_ok: req.health_ok,
        attestation_ok: req.attestation_ok,
        failure_reason: req.failure_reason,
        checked_at: chrono::Utc::now().to_rfc3339(),
    };
    health_store::insert_health_check(&state.db, &check)?;

    let consecutive_failures = health_store::count_consecutive_failures(&state.db, &id)?;
    let consecutive_successes = health_store::count_consecutive_successes(&state.db, &id)?;

    let counted_down = consecutive_failures >= state.down_after_failures;
    let imperfect_now = !check_ok;

    Ok(Json(AgentCheckIngestResponse {
        app_name,
        check_ok,
        deployment_exempt: false,
        counted_down,
        imperfect_now,
        consecutive_failures,
        consecutive_successes,
    }))
}

/// GET /api/v1/agents/{id}/checks
pub async fn list_checks(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<health_store::HealthCheckRow>>, AppError> {
    let checks = health_store::get_recent_checks(&state.db, &id, 50)?;
    Ok(Json(checks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::routes::build_router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let db = db::connect_and_migrate("sqlite://:memory:").unwrap();
        AppState::for_testing(db)
    }

    #[tokio::test]
    async fn challenge_returns_nonce() {
        let state = test_state();
        let app = build_router(state);

        let req = Request::builder()
            .uri("/api/v1/agents/challenge")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let challenge: AgentChallengeResponse = serde_json::from_slice(&body).unwrap();
        assert!(!challenge.nonce.is_empty());
        assert!(challenge.expires_in_seconds > 0);
    }

    #[tokio::test]
    async fn register_rejects_without_attestation_config() {
        let state = test_state();
        let nonce = state.nonce.issue().await;
        let app = build_router(state);

        // Without DD_INTEL_API_KEY, registration must fail — no insecure mode.
        let register_req = AgentRegisterRequest {
            intel_ta_token: "fake-token".into(),
            vm_name: "test-vm".into(),
            nonce,
            node_size: None,
            datacenter: None,
            github_owner: None,
        };

        let req = Request::builder()
            .uri("/api/v1/agents/register")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&register_req).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_nonexistent_agent_returns_404() {
        let state = test_state();
        let app = build_router(state);

        let req = Request::builder()
            .uri("/api/v1/agents/nonexistent-id")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
