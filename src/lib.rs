//! Signet library: the testable building blocks of the blind-signing service.
//!
//! The binary (`main.rs`) is a thin wrapper that wires these together and
//! serves over mTLS. Integration tests in `tests/` drive these modules and the
//! HTTP router directly.

pub mod config;
pub mod crypto;
pub mod db;
pub mod dedup;
pub mod error;
pub mod handlers;
pub mod identity;
pub mod keygen;
pub mod keystore;
pub mod prf;
pub mod ratelimit;
pub mod state;
pub mod tls;

use axum::routing::{get, post};
use axum::Router;
use identity::{IdentityAcceptor, IdentityPolicy};
use rustls::ServerConfig;
use state::AppState;
use std::sync::Arc;

/// Build the application router with all endpoints wired to `state`.
///
/// The PRF/dedup routes are mounted ONLY when `state.prf` is present (i.e.
/// the fail-closed boot policy in [`dedup::prepare_prf_boot`] enabled the
/// surface). Without it they 404 and the deployed /sign behavior is exactly
/// what it was before the PRF surface existed.
pub fn router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(handlers::healthz))
        .route("/sign", post(handlers::sign))
        .route("/key", get(handlers::get_key).post(handlers::create_key))
        .route("/key/rotate", post(handlers::rotate_key));
    if state.prf.is_some() {
        router = router
            .route("/prf/pairwise", post(handlers::prf_pairwise))
            .route("/prf/evaluate", post(handlers::prf_evaluate))
            .route("/prf/public-key", get(handlers::prf_public_key))
            .route("/prf/disclose", post(handlers::prf_disclose))
            .route("/dedup/register", post(handlers::dedup_register))
            .route("/dedup/release", post(handlers::dedup_release))
            .route("/dedup/reassign", post(handlers::dedup_reassign));
    }
    router.with_state(state)
}

/// Serve the router over mTLS on an already-bound `std::net::TcpListener`, with
/// the identity-pinning acceptor installed so every request carries the pinned
/// peer [`identity::ClientIdentity`].
///
/// This is the single serving path shared by the binary and the integration
/// tests, so both exercise the exact same identity-admission behavior.
pub async fn serve(
    listener: std::net::TcpListener,
    tls_config: Arc<ServerConfig>,
    policy: IdentityPolicy,
    app: Router,
) -> std::io::Result<()> {
    let acceptor = IdentityAcceptor::new(tls_config, policy);
    axum_server::from_tcp(listener)
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await
}
