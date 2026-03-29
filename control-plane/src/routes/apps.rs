use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::common::error::AppError;
use crate::state::AppState;
use crate::stores::app;

#[derive(Debug, Deserialize)]
pub struct CreateAppRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub owner_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateVersionRequest {
    pub version: String,
    #[serde(default)]
    pub image_digest: Option<String>,
    #[serde(default)]
    pub compose: Option<String>,
    #[serde(default)]
    pub config: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GrantDeployRequest {
    pub account_id: String,
    pub granted_by: String,
}

// -- App CRUD --

pub async fn list_apps(State(state): State<AppState>) -> Result<Json<Vec<app::AppRow>>, AppError> {
    Ok(Json(app::list_apps(&state.db)?))
}

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

pub async fn get_app(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<app::AppRow>, AppError> {
    Ok(Json(
        app::get_app(&state.db, &id)?.ok_or(AppError::NotFound)?,
    ))
}

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

// -- Versions --

pub async fn list_versions(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
) -> Result<Json<Vec<app::AppVersionRow>>, AppError> {
    app::get_app(&state.db, &app_id)?.ok_or(AppError::NotFound)?;
    Ok(Json(app::list_versions(&state.db, &app_id)?))
}

pub async fn create_version(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    Json(req): Json<CreateVersionRequest>,
) -> Result<(StatusCode, Json<app::AppVersionRow>), AppError> {
    app::get_app(&state.db, &app_id)?.ok_or(AppError::NotFound)?;
    if req.version.is_empty() {
        return Err(AppError::InvalidInput("version is required".into()));
    }
    let row = app::AppVersionRow {
        id: uuid::Uuid::new_v4().to_string(),
        app_id,
        version: req.version,
        image_digest: req.image_digest,
        compose: req.compose,
        config: req.config,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    app::insert_version(&state.db, &row)?;
    Ok((StatusCode::CREATED, Json(row)))
}

// -- Deploy Grants --

pub async fn grant_deploy(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    Json(req): Json<GrantDeployRequest>,
) -> Result<(StatusCode, Json<app::DeployGrantRow>), AppError> {
    let a = app::get_app(&state.db, &app_id)?.ok_or(AppError::NotFound)?;
    match &a.owner_id {
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
    app::insert_grant(&state.db, &row)?;
    Ok((StatusCode::CREATED, Json(row)))
}

pub async fn list_deployers(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
) -> Result<Json<Vec<app::DeployGrantRow>>, AppError> {
    app::get_app(&state.db, &app_id)?.ok_or(AppError::NotFound)?;
    Ok(Json(app::list_grants(&state.db, &app_id)?))
}

pub async fn revoke_deploy(
    State(state): State<AppState>,
    Path((app_id, account_id)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    if app::delete_grant(&state.db, &app_id, &account_id)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}
