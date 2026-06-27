//! Service error type and HTTP mapping.
//!
//! Errors deliberately carry minimal detail in the HTTP body: this is a
//! security boundary and we do not leak internal state, key material, or
//! cryptographic specifics to callers. Detailed context goes to the
//! structured log (never including secret payloads).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    /// Malformed request (bad base64, wrong field types, oversize input).
    BadRequest(&'static str),
    /// This (group_id, participant_id, version_id) already has a signature.
    AlreadyIssued,
    /// Per-participant or global rate limit exceeded.
    RateLimited,
    /// Group key does not exist and auto-create is disabled.
    NoSuchKey,
    /// Internal failure (DB, crypto, encoding). Never includes detail in body.
    Internal(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(m) => write!(f, "bad request: {m}"),
            AppError::AlreadyIssued => write!(f, "already issued"),
            AppError::RateLimited => write!(f, "rate limited"),
            AppError::NoSuchKey => write!(f, "no such key"),
            AppError::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::AlreadyIssued => (StatusCode::CONFLICT, "already_issued"),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            AppError::NoSuchKey => (StatusCode::NOT_FOUND, "no_such_key"),
            AppError::Internal(detail) => {
                // Log detail; never return it to the caller.
                tracing::error!(error = %detail, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        };
        // BadRequest carries a short static reason that is safe to surface.
        let message = match &self {
            AppError::BadRequest(m) => *m,
            AppError::AlreadyIssued => "a signature was already issued for this participation",
            AppError::RateLimited => "rate limit exceeded",
            AppError::NoSuchKey => "no key for this group",
            AppError::Internal(_) => "internal error",
        };
        (status, Json(json!({ "error": code, "message": message }))).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
