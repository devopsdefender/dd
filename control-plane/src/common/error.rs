use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

/// Application error type used across the control plane.
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

    #[error("external service error: {0}")]
    External(String),

    #[error("internal error")]
    Internal,
}

/// Convenience alias for Results carrying an AppError.
pub type AppResult<T> = Result<T, AppError>;

/// JSON error body returned to API clients.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl AppError {
    /// Map the error variant to an HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::InvalidInput(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::External(_) => StatusCode::BAD_GATEWAY,
            AppError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Machine-readable error code string.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::InvalidInput(_) => "invalid_input",
            AppError::Unauthorized => "unauthorized",
            AppError::Forbidden => "forbidden",
            AppError::NotFound => "not_found",
            AppError::Conflict(_) => "conflict",
            AppError::Config(_) => "config_error",
            AppError::External(_) => "external_error",
            AppError::Internal => "internal_error",
        }
    }

    /// Build the JSON error body for this error.
    pub fn to_error_body(&self) -> ErrorBody {
        ErrorBody {
            code: self.code().to_string(),
            message: self.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = self.to_error_body();
        let json = serde_json::to_string(&body).unwrap_or_default();
        (status, [("content-type", "application/json")], json).into_response()
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
        let parsed: ErrorBody = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "invalid_input");
        assert_eq!(parsed.message, "invalid input: bad field");
    }
}
