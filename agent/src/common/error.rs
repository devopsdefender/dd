use serde::Serialize;

/// Application-level error variants.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("external error: {0}")]
    External(String),

    #[error("internal error")]
    Internal,
}

/// Convenience alias used throughout the crate.
pub type AppResult<T> = Result<T, AppError>;

/// Wire-format body returned to callers on error.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
}

impl AppError {
    /// Short, stable error code suitable for machine consumption.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::InvalidInput(_) => "INVALID_INPUT",
            AppError::Unauthorized => "UNAUTHORIZED",
            AppError::Forbidden => "FORBIDDEN",
            AppError::NotFound => "NOT_FOUND",
            AppError::Conflict(_) => "CONFLICT",
            AppError::Config(_) => "CONFIG_ERROR",
            AppError::External(_) => "EXTERNAL_ERROR",
            AppError::Internal => "INTERNAL_ERROR",
        }
    }

    /// Build the serialisable error body.
    pub fn to_error_body(&self) -> ErrorBody {
        ErrorBody {
            code: self.code(),
            message: self.to_string(),
        }
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            AppError::InvalidInput(_) => axum::http::StatusCode::BAD_REQUEST,
            AppError::Unauthorized => axum::http::StatusCode::UNAUTHORIZED,
            AppError::Forbidden => axum::http::StatusCode::FORBIDDEN,
            AppError::NotFound => axum::http::StatusCode::NOT_FOUND,
            AppError::Conflict(_) => axum::http::StatusCode::CONFLICT,
            AppError::Config(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            AppError::External(_) => axum::http::StatusCode::BAD_GATEWAY,
            AppError::Internal => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = axum::Json(self.to_error_body());
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_body_serializes() {
        let err = AppError::InvalidInput("bad field".into());
        let body = err.to_error_body();
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("INVALID_INPUT"));
        assert!(json.contains("bad field"));
    }
}
