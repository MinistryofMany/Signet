//! Signet — hardened partially-blind RSA signing service for FreedInk vote
//! tokens.
//!
//! Thin entrypoint: load config, open the DB, build the mTLS server, and serve
//! the router defined in the library. See README.md for the integration
//! contract and operational setup.

use signet::config::Config;
use signet::db::Db;
use signet::ratelimit::RateLimiter;
use signet::state::AppState;
use signet::{router, tls};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!(error = %e, "fatal");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    // Install the ring-based default crypto provider for rustls 0.23.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "failed to install rustls crypto provider".to_string())?;

    let cfg = Config::from_env()?;

    let db = Db::open(&cfg.db_path)?;
    let state = Arc::new(AppState {
        db,
        kek: cfg.kek.clone(),
        rate_limiter: RateLimiter::new(
            cfg.rl_participant_max,
            cfg.rl_global_max,
            cfg.rl_window_secs,
        ),
        auto_create_keys: cfg.auto_create_keys,
        key_bits: cfg.key_bits,
    });

    let app = router(state);

    let tls_config = tls::build_server_config(&cfg.tls_cert, &cfg.tls_key, &cfg.client_ca)?;
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(tls_config);

    tracing::info!(
        bind = %cfg.bind,
        db = %cfg.db_path.display(),
        key_bits = cfg.key_bits,
        auto_create_keys = cfg.auto_create_keys,
        rl_participant_max = cfg.rl_participant_max,
        rl_global_max = cfg.rl_global_max,
        rl_window_secs = cfg.rl_window_secs,
        "signet starting (mTLS required)"
    );

    axum_server::bind_rustls(cfg.bind, rustls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| format!("server error: {e}"))?;

    Ok(())
}
