use axum::response::{Html, IntoResponse};

const UI_HTML: &str = include_str!("ui_root.html");

/// GET / - Serve the admin UI root page.
pub async fn ui_root() -> impl IntoResponse {
    Html(UI_HTML)
}

#[cfg(test)]
mod tests {
    use crate::db;
    use crate::routes::build_router;
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn ui_root_returns_html() {
        let db = db::connect_and_migrate("sqlite://:memory:").unwrap();
        let state = AppState::for_testing(db);
        let app = build_router(state);

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("DevOps Defender"));
    }
}
