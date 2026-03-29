use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::common::error::AppError;
use crate::state::AppState;
use crate::stores::app;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAppRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub owner_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantDeployRequest {
    pub account_id: String,
    pub granted_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAppVersionRequest {
    pub version: String,
    #[serde(default)]
    pub compose: Option<String>,
    #[serde(default)]
    pub config: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /api/v1/apps
pub async fn list_apps(State(state): State<AppState>) -> Result<Json<Vec<app::AppRow>>, AppError> {
    let apps = app::list_apps(&state.db)?;
    Ok(Json(apps))
}

/// POST /api/v1/apps
pub async fn create_app(
    State(state): State<AppState>,
    Json(req): Json<CreateAppRequest>,
) -> Result<(StatusCode, Json<app::AppRow>), AppError> {
    if req.name.is_empty() {
        return Err(AppError::InvalidInput("name is required".into()));
    }

    let row = app::AppRow {
        id: uuid::Uuid::new_v4().to_string(),
        name: req.name,
        description: req.description,
        owner_id: req.owner_id,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    app::insert_app(&state.db, &row)?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// GET /api/v1/apps/{id}
pub async fn get_app(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<app::AppRow>, AppError> {
    let row = app::get_app(&state.db, &id)?.ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

/// DELETE /api/v1/apps/{id}
pub async fn delete_app(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    if app::delete_app(&state.db, &id)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

/// GET /api/v1/apps/{id}/versions
pub async fn list_versions(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
) -> Result<Json<Vec<app::AppVersionRow>>, AppError> {
    // Verify app exists
    app::get_app(&state.db, &app_id)?.ok_or(AppError::NotFound)?;
    let versions = app::list_app_versions(&state.db, &app_id)?;
    Ok(Json(versions))
}

/// POST /api/v1/apps/{id}/versions
pub async fn create_version(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    Json(req): Json<CreateAppVersionRequest>,
) -> Result<(StatusCode, Json<app::AppVersionRow>), AppError> {
    // Verify app exists
    app::get_app(&state.db, &app_id)?.ok_or(AppError::NotFound)?;

    if req.version.is_empty() {
        return Err(AppError::InvalidInput("version is required".into()));
    }

    let row = app::AppVersionRow {
        id: uuid::Uuid::new_v4().to_string(),
        app_id,
        version: req.version,
        compose: req.compose,
        config: req.config,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    app::insert_app_version(&state.db, &row)?;
    Ok((StatusCode::CREATED, Json(row)))
}

// ---------------------------------------------------------------------------
// Deploy Grants
// ---------------------------------------------------------------------------

/// POST /api/v1/apps/{id}/deployers
pub async fn grant_deploy(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    Json(req): Json<GrantDeployRequest>,
) -> Result<(StatusCode, Json<app::DeployGrantRow>), AppError> {
    let app_row = app::get_app(&state.db, &app_id)?.ok_or(AppError::NotFound)?;

    // Only owner can grant deploy rights
    match &app_row.owner_id {
        Some(oid) if oid != &req.granted_by => return Err(AppError::Forbidden),
        None => return Err(AppError::InvalidInput("app has no owner".into())),
        _ => {}
    }

    let row = app::DeployGrantRow {
        id: uuid::Uuid::new_v4().to_string(),
        app_id,
        account_id: req.account_id,
        granted_by: req.granted_by,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    app::insert_deploy_grant(&state.db, &row)?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// GET /api/v1/apps/{id}/deployers
pub async fn list_deployers(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
) -> Result<Json<Vec<app::DeployGrantRow>>, AppError> {
    app::get_app(&state.db, &app_id)?.ok_or(AppError::NotFound)?;
    let grants = app::list_deploy_grants(&state.db, &app_id)?;
    Ok(Json(grants))
}

/// DELETE /api/v1/apps/{id}/deployers/{account_id}
pub async fn revoke_deploy(
    State(state): State<AppState>,
    Path((app_id, account_id)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    if app::delete_deploy_grant(&state.db, &app_id, &account_id)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use crate::db;
    use crate::routes::build_router;
    use crate::state::AppState;
    use crate::stores::app::AppRow;

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
    async fn create_and_list_apps() {
        let state = test_state();
        let app = build_router(state);

        // Create an app
        let req = Request::builder()
            .uri("/api/v1/apps")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"measurer","description":"TDX measurer"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = read_body(resp).await;
        let created: AppRow = serde_json::from_slice(&body).unwrap();
        assert_eq!(created.name, "measurer");

        // List apps
        let req = Request::builder()
            .uri("/api/v1/apps")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = read_body(resp).await;
        let apps: Vec<AppRow> = serde_json::from_slice(&body).unwrap();
        assert_eq!(apps.len(), 1);
    }

    #[tokio::test]
    async fn get_app_by_id() {
        let state = test_state();
        let app = build_router(state);

        // Create
        let req = Request::builder()
            .uri("/api/v1/apps")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"measurer"}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body(resp).await;
        let created: AppRow = serde_json::from_slice(&body).unwrap();

        // Get by ID
        let req = Request::builder()
            .uri(format!("/api/v1/apps/{}", created.id))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_nonexistent_app_returns_404() {
        let state = test_state();
        let app = build_router(state);

        let req = Request::builder()
            .uri("/api/v1/apps/nonexistent")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn duplicate_name_returns_409() {
        let state = test_state();
        let app = build_router(state);

        let body = r#"{"name":"measurer"}"#;
        let req = Request::builder()
            .uri("/api/v1/apps")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = Request::builder()
            .uri("/api/v1/apps")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn create_and_list_versions() {
        let state = test_state();
        let app = build_router(state);

        // Create app
        let req = Request::builder()
            .uri("/api/v1/apps")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"measurer"}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body(resp).await;
        let created: AppRow = serde_json::from_slice(&body).unwrap();

        // Create version
        let req = Request::builder()
            .uri(format!("/api/v1/apps/{}/versions", created.id))
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"version":"1.0.0"}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // List versions
        let req = Request::builder()
            .uri(format!("/api/v1/apps/{}/versions", created.id))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn version_for_nonexistent_app_returns_404() {
        let state = test_state();
        let app = build_router(state);

        let req = Request::builder()
            .uri("/api/v1/apps/nonexistent/versions")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"version":"1.0.0"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
