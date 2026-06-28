//! Signet — hardened partially-blind RSA signing service for FreedInk vote
//! tokens.
//!
//! Thin entrypoint: load config, open the DB, build the mTLS server, and serve
//! the router defined in the library. See README.md for the integration
//! contract and operational setup.

use signet::config::Config;
use signet::db::Db;
use signet::identity::IdentityPolicy;
use signet::keygen::KeygenService;
use signet::ratelimit::{KeyRateLimiter, RateLimiter};
use signet::state::AppState;
use signet::{router, serve, tls};
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

    let db = Arc::new(Db::open(&cfg.db_path)?);
    let keygen = KeygenService::new(
        db.clone(),
        cfg.kek.clone(),
        cfg.key_bits,
        cfg.keygen_max_concurrent,
    );
    let state = Arc::new(AppState {
        db,
        kek: cfg.kek.clone(),
        rate_limiter: RateLimiter::new(
            cfg.rl_participant_max,
            cfg.rl_global_max,
            cfg.rl_window_secs,
        ),
        key_rate_limiter: KeyRateLimiter::new(
            cfg.rl_key_identity_max,
            cfg.rl_key_global_max,
            cfg.rl_window_secs,
        ),
        keygen,
        auto_create_keys: cfg.auto_create_keys,
        key_bits: cfg.key_bits,
        info_prefix: cfg.info_prefix.clone(),
    });

    let policy = IdentityPolicy::new(cfg.allowed_client_ids.clone(), cfg.admin_ids.clone());
    if policy.client_list_is_open() {
        tracing::warn!(
            "SIGNET_ALLOWED_CLIENT_IDS is unset: ANY certificate chaining to \
             SIGNET_CLIENT_CA may call the signing/key endpoints. Set a dedicated \
             client allow-list for production."
        );
    }
    if policy.admin_list_is_empty() {
        tracing::warn!(
            "SIGNET_ADMIN_IDS is unset: /key/rotate is disabled (no admin identity). \
             Set an admin identity to enable rotation."
        );
    }

    let app = router(state);

    let tls_config = tls::build_server_config(&cfg.tls_cert, &cfg.tls_key, &cfg.client_ca)?;

    tracing::info!(
        bind = %cfg.bind,
        db = %cfg.db_path.display(),
        key_bits = cfg.key_bits,
        info_prefix = %cfg.info_prefix,
        auto_create_keys = cfg.auto_create_keys,
        rl_participant_max = cfg.rl_participant_max,
        rl_global_max = cfg.rl_global_max,
        rl_window_secs = cfg.rl_window_secs,
        keygen_max_concurrent = cfg.keygen_max_concurrent,
        rl_key_identity_max = cfg.rl_key_identity_max,
        rl_key_global_max = cfg.rl_key_global_max,
        allowed_client_ids = cfg.allowed_client_ids.len(),
        admin_ids = cfg.admin_ids.len(),
        "signet starting (mTLS required)"
    );

    let listener =
        std::net::TcpListener::bind(cfg.bind).map_err(|e| format!("bind {}: {e}", cfg.bind))?;
    serve(listener, tls_config, policy, app)
        .await
        .map_err(|e| format!("server error: {e}"))?;

    Ok(())
}
