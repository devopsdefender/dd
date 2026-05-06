use axum::http::StatusCode;
use axum::response::IntoResponse;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("not found")]
    NotFound,

    #[error("upstream: {0}")]
    Upstream(String),

    #[error("internal: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let (status, code) = match &self {
            Error::BadRequest(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            Error::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Error::Upstream(_) => (StatusCode::BAD_GATEWAY, "UPSTREAM"),
            Error::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL"),
        };
        let body = axum::Json(serde_json::json!({"code": code, "message": self.to_string()}));
        (status, body).into_response()
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Upstream(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::BadRequest(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Internal(e.to_string())
    }
}
