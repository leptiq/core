//! Proton-style API errors: `{"Code": N, "Error": "...", "Details": {...}}`.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

/// Proton API response codes used by this server.
pub mod code {
    pub const SUCCESS: i64 = 1000;
    pub const MULTI: i64 = 1001;
    pub const INVALID_VALUE: i64 = 2001;
    pub const NOT_ALLOWED: i64 = 2011;
    pub const ALREADY_EXISTS: i64 = 2500;
    pub const NOT_FOUND: i64 = 2501;
    pub const INVALID_ID: i64 = 2061;
    pub const APP_VERSION_MISSING: i64 = 5001;
    pub const APP_VERSION_BAD: i64 = 5003;
    pub const USERNAME_INVALID: i64 = 6003;
    pub const USERNAME_TAKEN: i64 = 12106;
    pub const PASSWORD_WRONG: i64 = 8002;
    pub const TWO_FA_WRONG: i64 = 8002;
    pub const HV_REQUIRED: i64 = 9001;
    pub const REAUTH_REQUIRED: i64 = 9101;
    pub const PAID_PLAN_REQUIRED: i64 = 10004;
    pub const REFRESH_TOKEN_INVALID: i64 = 10013;
    pub const CONFLICT: i64 = 2511;
    /// Pass: item/vault revision conflict.
    pub const REVISION_CONFLICT: i64 = 2001;
    /// Pass: session lock required.
    pub const SESSION_LOCKED: i64 = 300008;
    /// Pass: extra password required.
    pub const EXTRA_PASSWORD_REQUIRED: i64 = 300010;
    pub const FEATURE_DISABLED: i64 = 2032;
    pub const QUOTA_EXCEEDED: i64 = 300004;
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: i64,
    pub message: String,
    pub details: Option<Value>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: i64, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details: None,
        }
    }
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code::INVALID_VALUE,
            message,
        )
    }
    pub fn not_found(what: &str) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code::NOT_FOUND,
            format!("{what} not found"),
        )
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code::NOT_ALLOWED, message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code::CONFLICT, message)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, 401, "Invalid access token")
    }
    pub fn disabled(feature: &str) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code::FEATURE_DISABLED,
            format!("{feature} is not available on this server"),
        )
    }
    pub fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!("internal error: {err}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            500,
            "Internal server error",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "Code": self.code, "Error": self.message });
        body["Details"] = self.details.unwrap_or_else(|| json!({}));
        (self.status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => ApiError::not_found("Resource"),
            e => ApiError::internal(e),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::internal(e)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::bad_request(e.to_string())
    }
}
