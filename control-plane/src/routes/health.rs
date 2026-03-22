use axum::extract::State;
use axum::Json;

use crate::api::HealthResponse;
use crate::state::AppState;

/// GET /health
pub async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        boot_id: state.boot_id.clone(),
        git_sha: state.git_sha.clone(),
    })
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
    async fn health_returns_ok() {
        let state = test_state();
        let app = build_router(state);

        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert!(health.ok);
        assert_eq!(health.boot_id, "test-boot-id");
    }
}
