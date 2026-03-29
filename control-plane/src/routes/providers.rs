use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::common::error::AppError;
use crate::state::AppState;
use crate::stores::{app, measurer};

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterProviderRequest {
    pub name: String,
    pub public_key: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub mrtd: Option<String>,
    #[serde(default)]
    pub measurement_types: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitMeasurementRequest {
    pub image_digest: Option<String>,
    pub measurement_hash: String,
    pub signature: String,
    pub report: String,
    pub measurer_id: String,
    // For node measurements
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub node_mrtd: Option<String>,
}

// ---------------------------------------------------------------------------
// Provider CRUD
// ---------------------------------------------------------------------------

/// GET /api/v1/providers
pub async fn list_providers(
    State(state): State<AppState>,
) -> Result<Json<Vec<measurer::MeasurerRow>>, AppError> {
    let providers = measurer::list_measurers(&state.db)?;
    Ok(Json(providers))
}

/// POST /api/v1/providers
pub async fn register_provider(
    State(state): State<AppState>,
    Json(req): Json<RegisterProviderRequest>,
) -> Result<(StatusCode, Json<measurer::MeasurerRow>), AppError> {
    if req.name.is_empty() || req.public_key.is_empty() {
        return Err(AppError::InvalidInput(
            "name and public_key are required".into(),
        ));
    }

    let row = measurer::MeasurerRow {
        id: uuid::Uuid::new_v4().to_string(),
        name: req.name,
        public_key: req.public_key,
        agent_id: req.agent_id,
        mrtd: req.mrtd,
        measurement_types: req.measurement_types.unwrap_or_else(|| "app".into()),
        status: "active".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    measurer::insert_measurer(&state.db, &row)?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// DELETE /api/v1/providers/{id}
pub async fn revoke_provider(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    if measurer::revoke_measurer(&state.db, &id)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

// ---------------------------------------------------------------------------
// SKUs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSkuRequest {
    pub name: String,
    pub vcpu: i64,
    pub ram_gb: i64,
    #[serde(default)]
    pub gpu: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub available: Option<i64>,
}

/// POST /api/v1/providers/{id}/skus
pub async fn register_sku(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Json(req): Json<RegisterSkuRequest>,
) -> Result<(StatusCode, Json<measurer::SkuRow>), AppError> {
    // Verify provider exists
    measurer::get_measurer(&state.db, &provider_id)?.ok_or(AppError::NotFound)?;

    let row = measurer::SkuRow {
        id: uuid::Uuid::new_v4().to_string(),
        provider_id,
        name: req.name,
        vcpu: req.vcpu,
        ram_gb: req.ram_gb,
        gpu: req.gpu,
        region: req.region,
        available: req.available.unwrap_or(0),
        status: "active".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    measurer::insert_sku(&state.db, &row)?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// GET /api/v1/providers/{id}/skus
pub async fn list_provider_skus(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
) -> Result<Json<Vec<measurer::SkuRow>>, AppError> {
    let skus = measurer::list_skus_for_provider(&state.db, &provider_id)?;
    Ok(Json(skus))
}

/// GET /api/v1/skus — list all available SKUs across all providers
pub async fn list_all_skus(
    State(state): State<AppState>,
) -> Result<Json<Vec<measurer::SkuRow>>, AppError> {
    let skus = measurer::list_all_skus(&state.db)?;
    Ok(Json(skus))
}

// ---------------------------------------------------------------------------
// Measurements
// ---------------------------------------------------------------------------

/// POST /api/v1/apps/{app_id}/versions/{version_id}/measure
pub async fn submit_app_measurement(
    State(state): State<AppState>,
    Path((app_id, version_id)): Path<(String, String)>,
    Json(req): Json<SubmitMeasurementRequest>,
) -> Result<(StatusCode, Json<measurer::MeasurementRow>), AppError> {
    // Verify app and version exist
    app::get_app(&state.db, &app_id)?.ok_or(AppError::NotFound)?;
    app::get_app_version(&state.db, &version_id)?.ok_or(AppError::NotFound)?;

    // Verify measurer exists and is active
    let m = measurer::get_measurer(&state.db, &req.measurer_id)?.ok_or(AppError::NotFound)?;
    if m.status != "active" {
        return Err(AppError::Forbidden);
    }

    // TODO: verify Ed25519 signature against measurer's public key
    // For now, trust the submitted signature (will add crypto verification in Phase 4)

    let row = measurer::MeasurementRow {
        id: uuid::Uuid::new_v4().to_string(),
        measurer_id: req.measurer_id,
        measurement_type: "app".into(),
        app_id: Some(app_id),
        version_id: Some(version_id),
        image_digest: req.image_digest,
        agent_id: None,
        node_mrtd: None,
        measurement_hash: req.measurement_hash,
        signature: req.signature,
        report: req.report,
        status: "valid".into(),
        measured_at: chrono::Utc::now().to_rfc3339(),
    };
    measurer::insert_measurement(&state.db, &row)?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// GET /api/v1/apps/{app_id}/versions/{version_id}/measurements
pub async fn list_app_measurements(
    State(state): State<AppState>,
    Path((app_id, version_id)): Path<(String, String)>,
) -> Result<Json<Vec<measurer::MeasurementRow>>, AppError> {
    let measurements =
        measurer::list_measurements_for_app_version(&state.db, &app_id, &version_id)?;
    Ok(Json(measurements))
}

/// POST /api/v1/agents/{agent_id}/measure
pub async fn submit_node_measurement(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(req): Json<SubmitMeasurementRequest>,
) -> Result<(StatusCode, Json<measurer::MeasurementRow>), AppError> {
    // Verify measurer exists and is active
    let m = measurer::get_measurer(&state.db, &req.measurer_id)?.ok_or(AppError::NotFound)?;
    if m.status != "active" {
        return Err(AppError::Forbidden);
    }

    let row = measurer::MeasurementRow {
        id: uuid::Uuid::new_v4().to_string(),
        measurer_id: req.measurer_id,
        measurement_type: "node".into(),
        app_id: None,
        version_id: None,
        image_digest: None,
        agent_id: Some(agent_id),
        node_mrtd: req.node_mrtd,
        measurement_hash: req.measurement_hash,
        signature: req.signature,
        report: req.report,
        status: "valid".into(),
        measured_at: chrono::Utc::now().to_rfc3339(),
    };
    measurer::insert_measurement(&state.db, &row)?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// GET /api/v1/agents/{agent_id}/measurements
pub async fn list_node_measurements(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<Vec<measurer::MeasurementRow>>, AppError> {
    let measurements = measurer::list_measurements_for_agent(&state.db, &agent_id)?;
    Ok(Json(measurements))
}

#[cfg(test)]
mod tests {
    use crate::db;
    use crate::routes::build_router;
    use crate::state::AppState;
    use crate::stores::measurer::MeasurerRow;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let db = db::connect_and_migrate("sqlite://:memory:").unwrap();
        AppState::for_testing(db)
    }

    async fn read_body(resp: axum::response::Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn register_and_list_providers() {
        let state = test_state();
        let app = build_router(state);

        let req = Request::builder()
            .uri("/api/v1/providers")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"security-co","public_key":"base64key","measurement_types":"app,node"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = read_body(resp).await;
        let created: MeasurerRow = serde_json::from_slice(&body).unwrap();
        assert_eq!(created.name, "security-co");
        assert_eq!(created.status, "active");

        // List
        let req = Request::builder()
            .uri("/api/v1/providers")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn revoke_provider() {
        let state = test_state();
        let app = build_router(state);

        // Create
        let req = Request::builder()
            .uri("/api/v1/providers")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"dc-operator","public_key":"key123"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body(resp).await;
        let created: MeasurerRow = serde_json::from_slice(&body).unwrap();

        // Revoke
        let req = Request::builder()
            .uri(format!("/api/v1/providers/{}", created.id))
            .method("DELETE")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn submit_and_list_app_measurement() {
        let state = test_state();
        let app = build_router(state);

        // Create app
        let req = Request::builder()
            .uri("/api/v1/apps")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"test-app"}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body(resp).await;
        let created_app: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let app_id = created_app["id"].as_str().unwrap();

        // Create version
        let req = Request::builder()
            .uri(format!("/api/v1/apps/{app_id}/versions"))
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"version":"1.0.0"}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body(resp).await;
        let created_version: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let version_id = created_version["id"].as_str().unwrap();

        // Create provider
        let req = Request::builder()
            .uri("/api/v1/providers")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"security-co","public_key":"key123"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body(resp).await;
        let measurer: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let measurer_id = measurer["id"].as_str().unwrap();

        // Submit measurement
        let measurement_body = serde_json::json!({
            "measurer_id": measurer_id,
            "image_digest": "sha256:abc123",
            "measurement_hash": "hash456",
            "signature": "sig789",
            "report": "{\"layers\":[],\"safe\":true}"
        });
        let req = Request::builder()
            .uri(format!(
                "/api/v1/apps/{app_id}/versions/{version_id}/measure"
            ))
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&measurement_body).unwrap(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // List measurements
        let req = Request::builder()
            .uri(format!(
                "/api/v1/apps/{app_id}/versions/{version_id}/measurements"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
