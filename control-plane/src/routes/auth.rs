use axum::extract::State;
use axum::Json;

use crate::api::{AdminLoginRequest, AdminLoginResponse, AuthMeResponse};
use crate::auth::admin_session;
use crate::common::error::AppError;
use crate::state::AppState;
use crate::stores::session as session_store;

/// POST /api/v1/auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<AdminLoginRequest>,
) -> Result<Json<AdminLoginResponse>, AppError> {
    let admin_password = state
        .admin_password
        .as_ref()
        .ok_or(AppError::Config("admin password not configured".into()))?;

    // Check if it's a bcrypt hash or plain text
    let password_ok = if admin_password.starts_with("$2") {
        bcrypt::verify(&req.password, admin_password).unwrap_or(false)
    } else {
        req.password == *admin_password
    };

    if !password_ok {
        return Err(AppError::Unauthorized);
    }

    // Issue session token
    let raw_token = admin_session::issue_session_token();
    let token_hash = admin_session::hash_session_token(&raw_token);
    let token_prefix = admin_session::token_prefix_from_raw(&raw_token);

    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::hours(24);

    let session = session_store::SessionRow {
        id: uuid::Uuid::new_v4().to_string(),
        token_hash,
        token_prefix,
        created_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    };
    session_store::insert_session(&state.db, &session)?;

    Ok(Json(AdminLoginResponse {
        token: raw_token,
        expires_at,
    }))
}

/// GET /api/v1/auth/me
pub async fn me(State(_state): State<AppState>) -> Result<Json<AuthMeResponse>, AppError> {
    // Placeholder: in a full implementation this would extract auth from headers
    Ok(Json(AuthMeResponse {
        auth_method: "none".into(),
        github_login: None,
        expires_at: None,
    }))
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
    async fn login_with_correct_password() {
        let state = test_state();
        let app = build_router(state);

        let login_req = AdminLoginRequest {
            password: "test-admin-password".into(),
        };

        let req = Request::builder()
            .uri("/api/v1/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&login_req).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let login_resp: AdminLoginResponse = serde_json::from_slice(&body).unwrap();
        assert!(login_resp.token.starts_with("dds_"));
    }

    #[tokio::test]
    async fn login_with_wrong_password() {
        let state = test_state();
        let app = build_router(state);

        let login_req = AdminLoginRequest {
            password: "wrong-password".into(),
        };

        let req = Request::builder()
            .uri("/api/v1/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&login_req).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
