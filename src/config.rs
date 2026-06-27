//! Runtime configuration, loaded from environment variables.
//!
//! The KEK (key-encryption key) is the single most sensitive input. It is read
//! from `SIGNET_KEK` (32 raw bytes, hex- or base64-encoded) and is NEVER
//! persisted, logged, or returned by any endpoint. It exists only in process
//! memory.

use crate::keystore::Kek;
use std::net::SocketAddr;
use std::path::PathBuf;

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

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let bind: SocketAddr = env_or("SIGNET_BIND", "0.0.0.0:8443".parse().unwrap())?;
        let db_path = PathBuf::from(env_or("SIGNET_DB", "signet.db".to_string())?);
        let tls_cert = PathBuf::from(env_required("SIGNET_TLS_CERT")?);
        let tls_key = PathBuf::from(env_required("SIGNET_TLS_KEY")?);
        let client_ca = PathBuf::from(env_required("SIGNET_CLIENT_CA")?);

        let kek_raw = env_required("SIGNET_KEK")?;
        let kek = Kek::from_encoded(&kek_raw)
            .map_err(|e| format!("SIGNET_KEK is invalid: {e}"))?;

        let key_bits: usize = env_or("SIGNET_KEY_BITS", 2048usize)?;
        if !(2048..=4096).contains(&key_bits) || !key_bits.is_multiple_of(16) {
            return Err(format!(
                "SIGNET_KEY_BITS must be in [2048,4096] and a multiple of 16, got {key_bits}"
            ));
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
        })
    }
}
