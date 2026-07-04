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
    /// The group key is still being generated; the caller should retry shortly.
    /// Maps to HTTP 202 Accepted with `{ "status": "pending" }`.
    KeyPending,
    /// The caller's pinned client identity is not authorized for this endpoint
    /// (e.g. a non-admin calling `/key/rotate`, a non-PRF identity calling
    /// `/prf/*`, or an owner-handle mismatch on the dedup ledger). Maps to
    /// HTTP 403.
    Forbidden(&'static str),
    /// A referenced resource (e.g. a dedup entry ref) does not exist. Maps to
    /// HTTP 404 with the `not_found` code.
    NotFound(&'static str),
    /// The dedup value is already registered to a DIFFERENT owner. Maps to
    /// HTTP 409 with the `taken` code (one-credential-one-account).
    DedupTaken,
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
            AppError::KeyPending => write!(f, "key pending"),
            AppError::Forbidden(m) => write!(f, "forbidden: {m}"),
            AppError::NotFound(m) => write!(f, "not found: {m}"),
            AppError::DedupTaken => write!(f, "taken"),
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
            AppError::KeyPending => (StatusCode::ACCEPTED, "pending"),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            AppError::DedupTaken => (StatusCode::CONFLICT, "taken"),
            AppError::Internal(detail) => {
                // Log detail; never return it to the caller.
                tracing::error!(error = %detail, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        };
        // BadRequest / Forbidden carry a short static reason that is safe to
        // surface.
        let message = match &self {
            AppError::BadRequest(m) => *m,
            AppError::AlreadyIssued => "a signature was already issued for this participation",
            AppError::RateLimited => "rate limit exceeded",
            AppError::NoSuchKey => "no key for this group",
            AppError::KeyPending => "key is being generated; retry shortly",
            AppError::Forbidden(m) => *m,
            AppError::NotFound(m) => *m,
            AppError::DedupTaken => "this credential is already registered to another owner",
            AppError::Internal(_) => "internal error",
        };
        // The pending status uses `status` rather than `error` so clients can
        // distinguish "retry, this is expected" from a real failure.
        let body = if matches!(self, AppError::KeyPending) {
            json!({ "status": "pending", "message": message })
        } else {
            json!({ "error": code, "message": message })
        };
        (status, Json(body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
