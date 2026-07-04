//! Runtime configuration, loaded from environment variables.
//!
//! The KEK (key-encryption key) is the single most sensitive input. It is read
//! from `SIGNET_KEK` (32 raw bytes, hex- or base64-encoded) and is NEVER
//! persisted, logged, or returned by any endpoint. It exists only in process
//! memory. `SIGNET_IMPORT_PAIRWISE_HMAC` (the one-shot pairwise-secret import)
//! follows the same consume-zeroize-remove pattern.

use crate::keystore::Kek;
use std::net::SocketAddr;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
pub struct Config {
    /// Bind address for the HTTPS (mTLS) listener.
    pub bind: SocketAddr,
    /// SQLite database path.
    pub db_path: PathBuf,
    /// Server certificate chain (PEM).
    pub tls_cert: PathBuf,
    /// Server private key (PEM).
    pub tls_key: PathBuf,
    /// CA bundle (PEM) used to validate CLIENT certificates. mTLS is mandatory.
    pub client_ca: PathBuf,
    /// Key-encryption key for private-key-at-rest. Held only in memory.
    pub kek: Kek,
    /// Auto-create a group key on first `/sign` if none exists.
    pub auto_create_keys: bool,
    /// Per-participant rate limit: max sign requests per window.
    pub rl_participant_max: u32,
    /// Global rate limit: max sign requests per window across all participants.
    pub rl_global_max: u32,
    /// Rate-limit window length, in seconds.
    pub rl_window_secs: u64,
    /// Modulus size in bits for newly generated group keys.
    pub key_bits: usize,
    /// Allow-list of client identities (cert CN or DNS SAN) permitted to call
    /// the signing/key endpoints. Empty = any valid-chain cert (back-compat,
    /// warned at startup). Audit M1/M3.
    pub allowed_client_ids: std::collections::BTreeSet<String>,
    /// Allow-list of admin identities permitted to call `/key/rotate`. Empty =
    /// rotation disabled for everyone (fail-closed). Audit M1/M3.
    pub admin_ids: std::collections::BTreeSet<String>,
    /// Maximum concurrent key generations (bounded worker pool). Audit H1.
    pub keygen_max_concurrent: usize,
    /// Per-identity rate limit for `/key*` endpoints, per window. Audit H1.
    pub rl_key_identity_max: u32,
    /// Global rate limit for `/key*` endpoints, per window. Audit H1.
    pub rl_key_global_max: u32,
    /// Allow-list of client identities permitted to call the `/prf/*` and
    /// `/dedup/*` endpoints (SIGNET_PRF_CLIENT_IDS). Separate from — and
    /// NEVER granted by — `allowed_client_ids` or its open back-compat mode.
    /// Empty = PRF surface not configured (routes not mounted); an empty list
    /// with initialized service keys refuses startup (fail-closed).
    pub prf_client_ids: std::collections::BTreeSet<String>,
    /// The pinned VOPRF public key `pkS` (base64url, no padding), as printed
    /// by `signet init-service-keys`. Required whenever the PRF surface is
    /// enabled; a mismatch with the derived key refuses startup.
    pub dedup_pubkey_pin: Option<String>,
    /// One-shot pairwise-secret import (SIGNET_IMPORT_PAIRWISE_HMAC): the
    /// EXACT UTF-8 bytes of the live secret, consumed from the environment at
    /// load (removed + zeroized) and sealed into `service_keys` at boot.
    /// NOT trimmed: byte-stability with Minister's Node derivation requires
    /// the bytes verbatim.
    pub import_pairwise_hmac: Option<Zeroizing<Vec<u8>>>,
    /// Per-identity rate limit for the `/prf/*` + `/dedup/*` endpoints, per
    /// window (its own bucket, separate from /sign and /key*).
    pub rl_prf_identity_max: u32,
    /// Global rate limit for the `/prf/*` + `/dedup/*` endpoints, per window.
    pub rl_prf_global_max: u32,
}

/// Parse a comma-separated env var into a set of trimmed, non-empty identities.
fn env_id_set(key: &str) -> std::collections::BTreeSet<String> {
    match std::env::var(key) {
        Ok(v) => v
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
        Err(_) => std::collections::BTreeSet::new(),
    }
}

fn env_required(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| format!("missing required env var {key}"))
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> Result<T, String> {
    match std::env::var(key) {
        Ok(v) => v
            .parse()
            .map_err(|_| format!("env var {key} has invalid value {v:?}")),
        Err(_) => Ok(default),
    }
}

/// Consume `SIGNET_KEK` from the environment: parse it, zeroize the raw copy,
/// and remove the variable so it is not readable via /proc/<pid>/environ,
/// inherited by a child process, or surfaced by a crash dump walking the
/// environment block. The returned in-memory [`Kek`] is the only remaining
/// copy and is itself zeroized on drop.
///
/// SAFETY: `remove_var` is sound here because this is called from `main`
/// BEFORE the tokio runtime is built (audit L1) — for the serve path via
/// [`Config::from_env`] and for the `init-service-keys` one-shot directly —
/// so the process is still single-threaded and there is no concurrent env
/// access. Callers must preserve that ordering.
pub fn consume_kek_env() -> Result<Kek, String> {
    let mut kek_raw = env_required("SIGNET_KEK")?;
    let kek_result = Kek::from_encoded(&kek_raw);
    // Wipe the encoded KEK from our heap copy as soon as it is parsed,
    // regardless of whether parsing succeeded.
    kek_raw.zeroize();
    std::env::remove_var("SIGNET_KEK");
    kek_result.map_err(|e| format!("SIGNET_KEK is invalid: {e}"))
}

/// Consume `SIGNET_IMPORT_PAIRWISE_HMAC` (if set): take the EXACT UTF-8 bytes
/// (no trimming — byte-stability with Minister's live derivation), remove the
/// variable from the environment, and return the bytes in a zeroizing buffer.
/// Same single-threaded-before-runtime requirement as [`consume_kek_env`],
/// and the same bounded residual (see that function's note). Public because
/// the `init-service-keys` one-shot also consumes it (and then refuses).
pub fn consume_pairwise_import_env() -> Option<Zeroizing<Vec<u8>>> {
    match std::env::var("SIGNET_IMPORT_PAIRWISE_HMAC") {
        Ok(raw) => {
            std::env::remove_var("SIGNET_IMPORT_PAIRWISE_HMAC");
            Some(Zeroizing::new(raw.into_bytes()))
        }
        Err(_) => None,
    }
}

/// The SQLite database path (`SIGNET_DB`, default `signet.db`). Shared by the
/// serve path and the `init-service-keys` one-shot.
pub fn db_path_from_env() -> Result<PathBuf, String> {
    Ok(PathBuf::from(env_or("SIGNET_DB", "signet.db".to_string())?))
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let bind: SocketAddr = env_or("SIGNET_BIND", "0.0.0.0:8443".parse().unwrap())?;
        let db_path = db_path_from_env()?;
        let tls_cert = PathBuf::from(env_required("SIGNET_TLS_CERT")?);
        let tls_key = PathBuf::from(env_required("SIGNET_TLS_KEY")?);
        let client_ca = PathBuf::from(env_required("SIGNET_CLIENT_CA")?);

        let kek = consume_kek_env()?;
        let import_pairwise_hmac = consume_pairwise_import_env();

        let key_bits: usize = env_or("SIGNET_KEY_BITS", 2048usize)?;
        if !(2048..=4096).contains(&key_bits) || !key_bits.is_multiple_of(16) {
            return Err(format!(
                "SIGNET_KEY_BITS must be in [2048,4096] and a multiple of 16, got {key_bits}"
            ));
        }

        let keygen_max_concurrent: usize = env_or("SIGNET_KEYGEN_MAX_CONCURRENT", 2usize)?;
        if keygen_max_concurrent == 0 {
            return Err("SIGNET_KEYGEN_MAX_CONCURRENT must be >= 1".to_string());
        }

        Ok(Config {
            bind,
            db_path,
            tls_cert,
            tls_key,
            client_ca,
            kek,
            auto_create_keys: env_or("SIGNET_AUTO_CREATE_KEYS", true)?,
            rl_participant_max: env_or("SIGNET_RL_PARTICIPANT_MAX", 5u32)?,
            rl_global_max: env_or("SIGNET_RL_GLOBAL_MAX", 1000u32)?,
            rl_window_secs: env_or("SIGNET_RL_WINDOW_SECS", 60u64)?,
            key_bits,
            allowed_client_ids: env_id_set("SIGNET_ALLOWED_CLIENT_IDS"),
            admin_ids: env_id_set("SIGNET_ADMIN_IDS"),
            keygen_max_concurrent,
            rl_key_identity_max: env_or("SIGNET_RL_KEY_IDENTITY_MAX", 10u32)?,
            rl_key_global_max: env_or("SIGNET_RL_KEY_GLOBAL_MAX", 100u32)?,
            prf_client_ids: env_id_set("SIGNET_PRF_CLIENT_IDS"),
            dedup_pubkey_pin: std::env::var("SIGNET_DEDUP_PUBKEY_PIN").ok(),
            import_pairwise_hmac,
            // The pairwise oracle sits on the token-mint hot path; defaults
            // are generous but finite.
            rl_prf_identity_max: env_or("SIGNET_RL_PRF_IDENTITY_MAX", 1000u32)?,
            rl_prf_global_max: env_or("SIGNET_RL_PRF_GLOBAL_MAX", 5000u32)?,
        })
    }
}
