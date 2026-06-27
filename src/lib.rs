//! Signet library: the testable building blocks of the blind-signing service.
//!
//! The binary (`main.rs`) is a thin wrapper that wires these together and
//! serves over mTLS. Integration tests in `tests/` drive these modules and the
//! HTTP router directly.

pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod handlers;
pub mod keystore;
pub mod ratelimit;
pub mod state;
pub mod tls;

use axum::routing::{get, post};
use axum::Router;
use state::AppState;
use std::sync::Arc;

/// Build the application router with all endpoints wired to `state`.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(handlers::healthz))
        .route("/sign", post(handlers::sign))
        .route("/key", get(handlers::get_key).post(handlers::create_key))
        .route("/key/rotate", post(handlers::rotate_key))
        .with_state(state)
}
