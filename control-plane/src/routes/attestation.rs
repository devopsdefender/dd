use axum::extract::State;
use axum::Json;

use crate::api::CpAttestationResponse;
use crate::state::AppState;

/// GET /api/v1/attestation
pub async fn get_attestation(State(_state): State<AppState>) -> Json<CpAttestationResponse> {
    let Some(quote_b64) = std::env::var("DD_SELF_QUOTE_B64").ok() else {
        return Json(CpAttestationResponse::Unattested {
            attested: false,
            reason: "CP is not running in a TDX environment".into(),
        });
    };

    match dd_agent::attestation::tsm::parse_tdx_quote_base64(&quote_b64) {
        Ok(parsed) => Json(CpAttestationResponse::Attested {
            quote_b64,
            mrtd: parsed.mrtd_hex(),
            tcb_status: "self-reported".into(),
            attested: true,
        }),
        Err(e) => Json(CpAttestationResponse::Unattested {
            attested: false,
            reason: format!("DD_SELF_QUOTE_B64 is present but invalid: {e}"),
        }),
    }
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
    async fn reports_unattested_without_self_quote() {
        std::env::remove_var("DD_SELF_QUOTE_B64");

        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/api/v1/attestation")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: CpAttestationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed,
            CpAttestationResponse::Unattested {
                attested: false,
                reason: "CP is not running in a TDX environment".into(),
            }
        );
    }
}
