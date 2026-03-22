use axum::extract::State;
use axum::Json;

use crate::api::{
    RecentAgentStat, RecentAgentStatsResponse, RecentAppStat, RecentAppStatsResponse,
};
use crate::common::error::AppError;
use crate::state::AppState;

/// GET /api/v1/stats/apps
pub async fn app_stats(
    State(state): State<AppState>,
) -> Result<Json<RecentAppStatsResponse>, AppError> {
    let conn = state.db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT COALESCE(app_name, 'default') as app_name, \
             COUNT(*) as total_checks, \
             SUM(CASE WHEN health_ok = 1 THEN 1 ELSE 0 END) as healthy_checks \
             FROM app_health_checks \
             GROUP BY app_name \
             ORDER BY total_checks DESC",
        )
        .map_err(|_| AppError::Internal)?;

    let rows = stmt
        .query_map([], |row| {
            Ok(RecentAppStat {
                app_name: row.get::<_, String>(0)?,
                total_checks: row.get::<_, i64>(1)?,
                healthy_checks: row.get::<_, i64>(2)?,
            })
        })
        .map_err(|_| AppError::Internal)?;

    let mut stats = Vec::new();
    for row in rows {
        stats.push(row.map_err(|_| AppError::Internal)?);
    }

    Ok(Json(RecentAppStatsResponse { stats }))
}

/// GET /api/v1/stats/agents
pub async fn agent_stats(
    State(state): State<AppState>,
) -> Result<Json<RecentAgentStatsResponse>, AppError> {
    let conn = state.db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT a.id, a.vm_name, \
             COUNT(c.id) as total_checks, \
             SUM(CASE WHEN c.health_ok = 1 THEN 1 ELSE 0 END) as healthy_checks \
             FROM agents a \
             LEFT JOIN app_health_checks c ON a.id = c.agent_id \
             GROUP BY a.id \
             ORDER BY total_checks DESC",
        )
        .map_err(|_| AppError::Internal)?;

    let rows = stmt
        .query_map([], |row| {
            let id_str: String = row.get(0)?;
            let agent_id = uuid::Uuid::parse_str(&id_str).unwrap_or_else(|_| uuid::Uuid::new_v4());
            Ok(RecentAgentStat {
                agent_id,
                vm_name: row.get::<_, String>(1)?,
                total_checks: row.get::<_, i64>(2)?,
                healthy_checks: row.get::<_, Option<i64>>(3)?.unwrap_or(0),
            })
        })
        .map_err(|_| AppError::Internal)?;

    let mut stats = Vec::new();
    for row in rows {
        stats.push(row.map_err(|_| AppError::Internal)?);
    }

    Ok(Json(RecentAgentStatsResponse { stats }))
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
    async fn app_stats_empty() {
        let state = test_state();
        let app = build_router(state);

        let req = Request::builder()
            .uri("/api/v1/stats/apps")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let stats: RecentAppStatsResponse = serde_json::from_slice(&body).unwrap();
        assert!(stats.stats.is_empty());
    }
}
