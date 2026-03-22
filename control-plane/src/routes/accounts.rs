use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::api::{CreateAccountRequest, CreateAccountResponse};
use crate::auth::api_key;
use crate::common::error::AppError;
use crate::state::AppState;
use crate::stores::account as account_store;

/// POST /api/v1/accounts
pub async fn create_account(
    State(state): State<AppState>,
    Json(req): Json<CreateAccountRequest>,
) -> Result<(StatusCode, Json<CreateAccountResponse>), AppError> {
    let account_id = uuid::Uuid::new_v4();
    let (raw_key, key_hash) = api_key::issue_api_key();
    let key_prefix = api_key::key_prefix_from_raw(&raw_key);

    let account = account_store::AccountRow {
        id: account_id.to_string(),
        name: req.name,
        account_type: req.account_type.to_string(),
        api_key_hash: key_hash,
        api_key_prefix: key_prefix,
        github_login: req.github_login,
        github_org: req.github_org,
        created_at: chrono::Utc::now().to_rfc3339(),
        is_active: true,
    };

    account_store::insert_account(&state.db, &account)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateAccountResponse {
            account_id,
            api_key: raw_key,
        }),
    ))
}

/// GET /api/v1/accounts
pub async fn list_accounts(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let accounts = account_store::list_accounts(&state.db)?;
    let sanitized: Vec<serde_json::Value> = accounts
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id,
                "name": a.name,
                "account_type": a.account_type,
                "api_key_prefix": a.api_key_prefix,
                "github_login": a.github_login,
                "github_org": a.github_org,
                "created_at": a.created_at,
                "is_active": a.is_active,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "accounts": sanitized })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::routes::build_router;
    use crate::types::AccountType;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let db = db::connect_and_migrate("sqlite://:memory:").unwrap();
        AppState::for_testing(db)
    }

    #[tokio::test]
    async fn create_and_list_accounts() {
        let state = test_state();
        let app = build_router(state);

        let create_req = CreateAccountRequest {
            name: "Test Deployer".into(),
            account_type: AccountType::Deployer,
            github_login: Some("testuser".into()),
            github_org: None,
        };

        let req = Request::builder()
            .uri("/api/v1/accounts")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&create_req).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: CreateAccountResponse = serde_json::from_slice(&body).unwrap();
        assert!(created.api_key.starts_with("dd_live_"));
    }
}
