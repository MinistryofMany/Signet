//! Signet — hardened partially-blind RSA signing service for FreedInk vote
//! tokens, plus the Minister PRF/dedup surface (RFC 9497 VOPRF nullifiers and
//! the pairwise HMAC oracle).
//!
//! Thin entrypoint: load config, open the DB, run the fail-closed PRF boot
//! policy, build the mTLS server, and serve the router defined in the
//! library. Also hosts the one-shot `init-service-keys` mode. See README.md
//! for the integration contract and operational setup.

use signet::config::{self, Config};
use signet::db::Db;
use signet::dedup::{self, PrfBoot, PrfBootArgs};
use signet::identity::IdentityPolicy;
use signet::keygen::KeygenService;
use signet::ratelimit::{KeyRateLimiter, RateLimiter};
use signet::state::{AppState, PrfState};
use signet::{router, serve, tls};
use std::sync::Arc;

fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // One-shot service-key initialization (`signet init-service-keys` or
    // SIGNET_INIT_SERVICE_KEYS=1): mint + seal the nullifier master seed,
    // print pkS for pinning, and exit. Deliberately NOT part of ordinary
    // boot — ordinary boot never generates key material (key-fork guard).
    if is_init_mode() {
        run_init_service_keys();
        return;
    }

    // Parse configuration BEFORE the async runtime exists (audit L1). Config
    // loading consumes secret environment variables (`SIGNET_KEK`,
    // `SIGNET_IMPORT_PAIRWISE_HMAC`) via `std::env::remove_var`, which is
    // only sound while the process is still single-threaded. A
    // `#[tokio::main]` entrypoint would spawn the runtime's worker threads
    // first and make that env mutation a data race.
    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!(error = %e, "fatal");
            std::process::exit(1);
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "fatal: failed to build the tokio runtime");
            std::process::exit(1);
        }
    };

    if let Err(e) = runtime.block_on(run(cfg)) {
        tracing::error!(error = %e, "fatal");
        std::process::exit(1);
    }
}

fn is_init_mode() -> bool {
    std::env::args().nth(1).as_deref() == Some("init-service-keys")
        || std::env::var("SIGNET_INIT_SERVICE_KEYS").is_ok_and(|v| v == "1")
}

/// Mint + seal the master seed (one-shot), print the derived public key `pkS`
/// on stdout — and ONLY `pkS`, never seed bytes — then exit. The operator
/// pins the printed value as `SIGNET_DEDUP_PUBKEY_PIN` (and Minister's
/// `MINISTER_SIGNET_DEDUP_PUBKEY`).
///
/// Guarded: a node configured with a pubkey pin (its seed exists elsewhere by
/// definition) or a pairwise import must NEVER mint — see
/// [`dedup::check_init_preconditions`]. This closes the fork where a stray
/// `SIGNET_INIT_SERVICE_KEYS=1` in a persistent unit env mints a fresh seed
/// on a replica racing its keystore restore.
fn run_init_service_keys() {
    let result = (|| -> Result<String, String> {
        let pin_configured = std::env::var("SIGNET_DEDUP_PUBKEY_PIN").is_ok();
        // Consume (zeroize + remove) the import variable BEFORE refusing on
        // it, so the secret does not linger in the runtime environment.
        let import = config::consume_pairwise_import_env();
        dedup::check_init_preconditions(pin_configured, import.is_some())?;
        let kek = config::consume_kek_env()?;
        let db_path = config::db_path_from_env()?;
        let db = Db::open(&db_path)?;
        dedup::init_service_keys(&db, &kek)
    })();
    match result {
        Ok(pk) => {
            tracing::info!(
                "service keys initialized; pin the printed public key as \
                 SIGNET_DEDUP_PUBKEY_PIN and Minister's MINISTER_SIGNET_DEDUP_PUBKEY"
            );
            println!("{pk}");
        }
        Err(e) => {
            tracing::error!(error = %e, "init-service-keys failed");
            std::process::exit(1);
        }
    }
}

async fn run(mut cfg: Config) -> Result<(), String> {
    // Install the ring-based default crypto provider for rustls 0.23.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "failed to install rustls crypto provider".to_string())?;

    let db = Arc::new(Db::open(&cfg.db_path)?);

    // Fail-closed PRF boot policy: decides whether the PRF surface mounts,
    // refuses startup on any inconsistent state (seed absent while
    // configured, empty allow-list with initialized keys, missing or
    // mismatched public-key pin, double import).
    let prf_boot = dedup::prepare_prf_boot(
        &db,
        &cfg.kek,
        PrfBootArgs {
            prf_clients_configured: !cfg.prf_client_ids.is_empty(),
            dedup_pubkey_pin: cfg.dedup_pubkey_pin.as_deref(),
            import_pairwise: cfg.import_pairwise_hmac.take(),
        },
    )?;
    let prf = match prf_boot {
        PrfBoot::Disabled => None,
        PrfBoot::Enabled(keys) => Some(PrfState {
            keys: *keys,
            allowed_client_ids: cfg.prf_client_ids.clone(),
            rate_limiter: KeyRateLimiter::new(
                cfg.rl_prf_identity_max,
                cfg.rl_prf_global_max,
                cfg.rl_window_secs,
            ),
        }),
    };
    let prf_enabled = prf.is_some();
    let prf_pairwise_ready = prf.as_ref().is_some_and(|p| p.keys.has_pairwise());

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
        prf,
    });

    let policy = IdentityPolicy::new(
        cfg.allowed_client_ids.clone(),
        cfg.admin_ids.clone(),
        cfg.prf_client_ids.clone(),
    );
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
        auto_create_keys = cfg.auto_create_keys,
        rl_participant_max = cfg.rl_participant_max,
        rl_global_max = cfg.rl_global_max,
        rl_window_secs = cfg.rl_window_secs,
        keygen_max_concurrent = cfg.keygen_max_concurrent,
        rl_key_identity_max = cfg.rl_key_identity_max,
        rl_key_global_max = cfg.rl_key_global_max,
        allowed_client_ids = cfg.allowed_client_ids.len(),
        admin_ids = cfg.admin_ids.len(),
        prf_enabled,
        prf_client_ids = cfg.prf_client_ids.len(),
        prf_pairwise_ready,
        rl_prf_identity_max = cfg.rl_prf_identity_max,
        rl_prf_global_max = cfg.rl_prf_global_max,
        "signet starting (mTLS required)"
    );

    let listener =
        std::net::TcpListener::bind(cfg.bind).map_err(|e| format!("bind {}: {e}", cfg.bind))?;
    serve(listener, tls_config, policy, app)
        .await
        .map_err(|e| format!("server error: {e}"))?;

    Ok(())
}
