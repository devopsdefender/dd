use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::common::error::AppError;
use crate::state::AppState;
use crate::stores::provider;

#[derive(Debug, Deserialize)]
pub struct RegisterProviderRequest {
    pub name: String,
    pub public_key: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub mrtd: Option<String>,
}

#[derive(Debug, Deserialize)]
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

// -- Providers --

pub async fn list_providers(
    State(state): State<AppState>,
) -> Result<Json<Vec<provider::ProviderRow>>, AppError> {
    Ok(Json(provider::list_providers(&state.db)?))
}

pub async fn register_provider(
    State(state): State<AppState>,
    Json(req): Json<RegisterProviderRequest>,
) -> Result<(StatusCode, Json<provider::ProviderRow>), AppError> {
    if req.name.is_empty() || req.public_key.is_empty() {
        return Err(AppError::InvalidInput(
            "name and public_key are required".into(),
        ));
    }
    let row = provider::ProviderRow {
        id: uuid::Uuid::new_v4().to_string(),
        name: req.name,
        public_key: req.public_key,
        agent_id: req.agent_id,
        mrtd: req.mrtd,
        status: "active".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    provider::insert_provider(&state.db, &row)?;
    Ok((StatusCode::CREATED, Json(row)))
}

pub async fn revoke_provider(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    if provider::revoke_provider(&state.db, &id)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

// -- SKUs --

pub async fn register_sku(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Json(req): Json<RegisterSkuRequest>,
) -> Result<(StatusCode, Json<provider::SkuRow>), AppError> {
    provider::get_provider(&state.db, &provider_id)?.ok_or(AppError::NotFound)?;
    let row = provider::SkuRow {
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
    provider::insert_sku(&state.db, &row)?;
    Ok((StatusCode::CREATED, Json(row)))
}

pub async fn list_provider_skus(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
) -> Result<Json<Vec<provider::SkuRow>>, AppError> {
    Ok(Json(provider::list_skus(&state.db, &provider_id)?))
}

pub async fn list_all_skus(
    State(state): State<AppState>,
) -> Result<Json<Vec<provider::SkuRow>>, AppError> {
    Ok(Json(provider::list_all_skus(&state.db)?))
}
