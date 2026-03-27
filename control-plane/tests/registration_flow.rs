//! Integration tests for the agent registration + attestation flow.
//!
//! Tests the full lifecycle: challenge → register → heartbeat → deploy → health checks.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use dd_control_plane::api::{
    AgentChallengeResponse, AgentCheckIngestRequest, AgentCheckIngestResponse,
    AgentRegisterRequest, AgentRegisterResponse, DeployRequest, DeployResponse, HealthResponse,
};
use dd_control_plane::db;
use dd_control_plane::routes::build_router;
use dd_control_plane::state::AppState;
use dd_control_plane::stores::agent as agent_store;

fn test_state() -> AppState {
    let db = db::connect_and_migrate("sqlite://:memory:").unwrap();
    AppState::for_testing(db)
}

fn json_request(method: &str, uri: &str, body: Option<String>) -> Request<Body> {
    let mut builder = Request::builder().uri(uri).method(method);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    builder
        .body(body.map(Body::from).unwrap_or(Body::empty()))
        .unwrap()
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

// ---------------------------------------------------------------------------
// Full registration flow: challenge → register → verify agent exists
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_registration_flow() {
    let state = test_state();

    // Step 1: Get challenge nonce
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request("GET", "/api/v1/agents/challenge", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let challenge: AgentChallengeResponse =
        serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert!(!challenge.nonce.is_empty());
    assert!(challenge.expires_in_seconds > 0);

    // Step 2: Register agent with the nonce
    let register_req = AgentRegisterRequest {
        intel_ta_token: "fake-attestation-token".into(),
        vm_name: "integration-test-vm".into(),
        nonce: challenge.nonce.clone(),
        node_size: Some("standard".into()),
        datacenter: Some("us-east-1".into()),
        github_owner: Some("devopsdefender".into()),
    };

    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/agents/register",
            Some(serde_json::to_string(&register_req).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let register_resp: AgentRegisterResponse =
        serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert!(!register_resp.tunnel_token.is_empty());
    assert!(!register_resp.hostname.is_empty());
    let agent_id = register_resp.agent_id;

    // Step 3: Verify agent appears in agent list
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request("GET", "/api/v1/agents", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let agents: Vec<agent_store::AgentRow> =
        serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].vm_name, "integration-test-vm");
    assert_eq!(agents[0].node_size, Some("standard".into()));
    assert_eq!(agents[0].datacenter, Some("us-east-1".into()));

    // Step 4: Get agent by ID
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "GET",
            &format!("/api/v1/agents/{agent_id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let agent: agent_store::AgentRow = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(agent.vm_name, "integration-test-vm");
    assert_eq!(agent.status, "undeployed");
    assert_eq!(agent.registration_state, "ready");
}

// ---------------------------------------------------------------------------
// Heartbeat flow: register → heartbeat → verify timestamp updates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn heartbeat_updates_agent() {
    let state = test_state();

    // Register an agent
    let register_req = AgentRegisterRequest {
        intel_ta_token: "fake-token".into(),
        vm_name: "heartbeat-test-vm".into(),
        nonce: "test-nonce".into(),
        node_size: None,
        datacenter: None,
        github_owner: None,
    };

    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/agents/register",
            Some(serde_json::to_string(&register_req).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let register_resp: AgentRegisterResponse =
        serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let agent_id = register_resp.agent_id;

    // Send heartbeat
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/agents/{agent_id}/heartbeat"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify heartbeat timestamp is set
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "GET",
            &format!("/api/v1/agents/{agent_id}"),
            None,
        ))
        .await
        .unwrap();
    let agent: agent_store::AgentRow = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert!(agent.last_heartbeat_at.is_some());
}

// ---------------------------------------------------------------------------
// Heartbeat for nonexistent agent returns 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn heartbeat_nonexistent_agent_returns_404() {
    let state = test_state();
    let app = build_router(state);

    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/agents/00000000-0000-0000-0000-000000000000/heartbeat",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Deploy flow: register → deploy → verify deployment created
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_then_deploy() {
    let state = test_state();

    // Register an agent first
    let register_req = AgentRegisterRequest {
        intel_ta_token: "fake-token".into(),
        vm_name: "deploy-test-vm".into(),
        nonce: "test-nonce".into(),
        node_size: Some("standard".into()),
        datacenter: None,
        github_owner: None,
    };

    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/agents/register",
            Some(serde_json::to_string(&register_req).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let register_resp: AgentRegisterResponse =
        serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let agent_id = register_resp.agent_id;

    // Deploy an app to the agent
    let deploy_req = DeployRequest {
        compose: "version: '3'\nservices:\n  web:\n    image: nginx:latest".into(),
        config: None,
        app_name: Some("test-app".into()),
        app_version: Some("1.0.0".into()),
        agent_name: None,
        node_size: Some("standard".into()),
        datacenter: None,
        dry_run: None,
    };

    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/deploy",
            Some(serde_json::to_string(&deploy_req).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let deploy_resp: DeployResponse = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(deploy_resp.agent_id, agent_id);

    // Verify deployment appears in list
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request("GET", "/api/v1/deployments", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_bytes(resp).await;
    let deps: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0]["app_name"], "test-app");
    assert_eq!(deps[0]["app_version"], "1.0.0");
    assert_eq!(deps[0]["status"], "deploying");

    // Verify agent status changed to deploying
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "GET",
            &format!("/api/v1/agents/{agent_id}"),
            None,
        ))
        .await
        .unwrap();
    let agent: agent_store::AgentRow = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(agent.status, "deploying");
}

// ---------------------------------------------------------------------------
// Dry-run deploy does not create actual deployment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dry_run_deploy_does_not_persist() {
    let state = test_state();

    // Register an agent
    let register_req = AgentRegisterRequest {
        intel_ta_token: "fake-token".into(),
        vm_name: "dryrun-test-vm".into(),
        nonce: "test-nonce".into(),
        node_size: None,
        datacenter: None,
        github_owner: None,
    };

    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/agents/register",
            Some(serde_json::to_string(&register_req).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Deploy with dry_run = true
    let deploy_req = DeployRequest {
        compose: "version: '3'".into(),
        config: None,
        app_name: Some("test-app".into()),
        app_version: None,
        agent_name: None,
        node_size: None,
        datacenter: None,
        dry_run: Some(true),
    };

    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/deploy",
            Some(serde_json::to_string(&deploy_req).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify no deployments were actually created
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request("GET", "/api/v1/deployments", None))
        .await
        .unwrap();
    let deps: Vec<serde_json::Value> = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert!(deps.is_empty());
}

// ---------------------------------------------------------------------------
// Health check ingestion flow: register → ingest checks → verify counters
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_check_ingestion_flow() {
    let state = test_state();

    // Register an agent
    let register_req = AgentRegisterRequest {
        intel_ta_token: "fake-token".into(),
        vm_name: "health-test-vm".into(),
        nonce: "test-nonce".into(),
        node_size: None,
        datacenter: None,
        github_owner: None,
    };

    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/agents/register",
            Some(serde_json::to_string(&register_req).unwrap()),
        ))
        .await
        .unwrap();
    let register_resp: AgentRegisterResponse =
        serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let agent_id = register_resp.agent_id;

    // Ingest a healthy check
    let check_req = AgentCheckIngestRequest {
        app_name: Some("test-app".into()),
        health_ok: true,
        attestation_ok: true,
        failure_reason: None,
    };

    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/agents/{agent_id}/checks"),
            Some(serde_json::to_string(&check_req).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let check_resp: AgentCheckIngestResponse =
        serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert!(check_resp.check_ok);
    assert!(!check_resp.counted_down);
    assert_eq!(check_resp.consecutive_successes, 1);
    assert_eq!(check_resp.consecutive_failures, 0);

    // Ingest a failing check
    let check_req = AgentCheckIngestRequest {
        app_name: Some("test-app".into()),
        health_ok: false,
        attestation_ok: true,
        failure_reason: Some("connection refused".into()),
    };

    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/agents/{agent_id}/checks"),
            Some(serde_json::to_string(&check_req).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let check_resp: AgentCheckIngestResponse =
        serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert!(!check_resp.check_ok);
    assert_eq!(check_resp.consecutive_failures, 1);

    // Verify checks appear in the checks list
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "GET",
            &format!("/api/v1/agents/{agent_id}/checks"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let checks: Vec<serde_json::Value> = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(checks.len(), 2);
}

// ---------------------------------------------------------------------------
// Agent lifecycle: register → reset → delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_reset_and_delete() {
    let state = test_state();

    // Register
    let register_req = AgentRegisterRequest {
        intel_ta_token: "fake-token".into(),
        vm_name: "lifecycle-test-vm".into(),
        nonce: "test-nonce".into(),
        node_size: None,
        datacenter: None,
        github_owner: None,
    };

    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/agents/register",
            Some(serde_json::to_string(&register_req).unwrap()),
        ))
        .await
        .unwrap();
    let register_resp: AgentRegisterResponse =
        serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let agent_id = register_resp.agent_id;

    // Reset agent
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/agents/{agent_id}/reset"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify reset state
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "GET",
            &format!("/api/v1/agents/{agent_id}"),
            None,
        ))
        .await
        .unwrap();
    let agent: agent_store::AgentRow = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(agent.status, "undeployed");
    assert_eq!(agent.registration_state, "pending");

    // Delete agent
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "DELETE",
            &format!("/api/v1/agents/{agent_id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify agent is gone
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "GET",
            &format!("/api/v1/agents/{agent_id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Health endpoint returns expected fields
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_endpoint_returns_boot_id_and_sha() {
    let state = test_state();
    let app = build_router(state);

    let resp = app
        .oneshot(json_request("GET", "/health", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let health: HealthResponse = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert!(health.ok);
    assert_eq!(health.boot_id, "test-boot-id");
    assert_eq!(health.git_sha, "test-sha");
}

// ---------------------------------------------------------------------------
// Multiple agents: deploy picks correct node_size
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deploy_matches_node_size() {
    let state = test_state();

    // Register a "tiny" agent
    let register_req = AgentRegisterRequest {
        intel_ta_token: "fake-token".into(),
        vm_name: "tiny-vm".into(),
        nonce: "test-nonce".into(),
        node_size: Some("tiny".into()),
        datacenter: None,
        github_owner: None,
    };
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/agents/register",
            Some(serde_json::to_string(&register_req).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Register an "llm" agent
    let register_req = AgentRegisterRequest {
        intel_ta_token: "fake-token".into(),
        vm_name: "llm-vm".into(),
        nonce: "test-nonce".into(),
        node_size: Some("llm".into()),
        datacenter: None,
        github_owner: None,
    };
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/agents/register",
            Some(serde_json::to_string(&register_req).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let llm_agent: AgentRegisterResponse = serde_json::from_slice(&body_bytes(resp).await).unwrap();

    // Deploy requesting "llm" node_size should pick the llm agent
    let deploy_req = DeployRequest {
        compose: "version: '3'".into(),
        config: None,
        app_name: Some("llm-app".into()),
        app_version: None,
        agent_name: None,
        node_size: Some("llm".into()),
        datacenter: None,
        dry_run: None,
    };
    let app = build_router(state.clone());
    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/deploy",
            Some(serde_json::to_string(&deploy_req).unwrap()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let deploy_resp: DeployResponse = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(deploy_resp.agent_id, llm_agent.agent_id);
}
