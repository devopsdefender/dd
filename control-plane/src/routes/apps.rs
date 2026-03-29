use axum::extract::State;
use axum::Json;

use crate::common::error::AppError;
use crate::state::AppState;
use crate::stores::app as app_store;

/// GET /api/v1/apps
pub async fn list_apps(
    State(state): State<AppState>,
) -> Result<Json<Vec<app_store::AppRow>>, AppError> {
    let apps = app_store::list_apps(&state.db)?;
    Ok(Json(apps))
}
