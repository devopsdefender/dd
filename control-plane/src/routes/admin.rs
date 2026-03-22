use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use rusqlite::params;

use crate::common::error::AppError;
use crate::state::AppState;

/// Trusted MRTD measurement entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeasurementEntry {
    pub id: String,
    pub mrtd: String,
    pub label: Option<String>,
    pub created_at: String,
}

/// Request body for adding a new trusted measurement.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AddMeasurementRequest {
    pub mrtd: String,
    pub label: Option<String>,
}

/// GET /api/v1/admin/measurements
pub async fn list_measurements(
    State(state): State<AppState>,
) -> Result<Json<Vec<MeasurementEntry>>, AppError> {
    let conn = state.db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, mrtd, label, created_at FROM trusted_mrtds ORDER BY created_at DESC")
        .map_err(|_| AppError::Internal)?;

    let rows = stmt
        .query_map([], |row| {
            Ok(MeasurementEntry {
                id: row.get("id")?,
                mrtd: row.get("mrtd")?,
                label: row.get("label")?,
                created_at: row.get("created_at")?,
            })
        })
        .map_err(|_| AppError::Internal)?;

    let mut entries = Vec::new();
    for row in rows {
        entries.push(row.map_err(|_| AppError::Internal)?);
    }

    Ok(Json(entries))
}

/// POST /api/v1/admin/measurements
pub async fn add_measurement(
    State(state): State<AppState>,
    Json(req): Json<AddMeasurementRequest>,
) -> Result<(StatusCode, Json<MeasurementEntry>), AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let conn = state.db.lock().unwrap();
    conn.execute(
        "INSERT INTO trusted_mrtds (id, mrtd, label, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![id, req.mrtd, req.label, now],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::Conflict("MRTD already trusted".into())
        } else {
            AppError::Internal
        }
    })?;

    Ok((
        StatusCode::CREATED,
        Json(MeasurementEntry {
            id,
            mrtd: req.mrtd,
            label: req.label,
            created_at: now,
        }),
    ))
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
    async fn add_and_list_measurements() {
        let state = test_state();
        let app = build_router(state);

        let add_req = AddMeasurementRequest {
            mrtd: "abc123def456".into(),
            label: Some("test-image-v1".into()),
        };

        let req = Request::builder()
            .uri("/api/v1/admin/measurements")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&add_req).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
}
