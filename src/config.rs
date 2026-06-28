//! Runtime configuration, loaded from environment variables.
//!
//! The KEK (key-encryption key) is the single most sensitive input. It is read
//! from `SIGNET_KEK` (32 raw bytes, hex- or base64-encoded) and is NEVER
//! persisted, logged, or returned by any endpoint. It exists only in process
//! memory.

use crate::keystore::Kek;
use std::net::SocketAddr;
use std::path::PathBuf;
use zeroize::Zeroize;

/// Default public-metadata namespace prefix. Preserves FreedInk's wire format
/// (`freedink-vote:<version_id>`) when `SIGNET_INFO_PREFIX` is unset.
pub const DEFAULT_INFO_PREFIX: &str = "freedink-vote";

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
    /// Public-metadata namespace prefix. The signed metadata is
    /// `<info_prefix>:<version_id>` (see [`crate::crypto::version_info`]);
    /// default `freedink-vote` (FreedInk wire format). A Deforum deployment sets
    /// `deforum-ban`. The client, this signer, and the verifier must agree on it
    /// byte-for-byte or signatures fail closed at redemption. Validated at startup.
    pub info_prefix: String,
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

/// Validate the configured metadata prefix.
///
/// The prefix is half of the public-metadata bytes `<prefix>:<version_id>` (see
/// [`crate::crypto::version_info`]); the client that blinds, this signer, and the
/// verifier that redeems must all agree on it byte-for-byte, or the per-metadata
/// key derivation diverges and every signature fails closed at redemption. To
/// turn that silent, redemption-time failure into a loud, startup-time one, we
/// constrain the value to an unambiguous ASCII charset.
///
/// Allowed: ASCII letters, digits, `-`, `_`, `.` (1..=64 of them). This is
/// byte-stable across hosts — no Unicode-normalization or whitespace drift
/// between the signer and the client/verifier — and it subsumes the `:`
/// separator (the metadata is `<prefix>:<version_id>`, so the prefix must not
/// itself contain the separator). Both known consumers (`freedink-vote`,
/// `deforum-ban`) are within this set; anything outside it is far more likely an
/// accidental mismatch than an intended namespace, so we fail closed at startup.
fn validate_info_prefix(prefix: String) -> Result<String, String> {
    const MAX_INFO_PREFIX_LEN: usize = 64;
    if prefix.is_empty() {
        return Err("SIGNET_INFO_PREFIX must not be empty".to_string());
    }
    if prefix.len() > MAX_INFO_PREFIX_LEN {
        return Err(format!(
            "SIGNET_INFO_PREFIX must be at most {MAX_INFO_PREFIX_LEN} bytes, got {}",
            prefix.len()
        ));
    }
    if let Some(bad) = prefix
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    {
        return Err(format!(
            "SIGNET_INFO_PREFIX may contain only ASCII letters, digits, '-', '_', '.' \
             (the ':' separator is added automatically); got {bad:?}"
        ));
    }
    Ok(prefix)
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let bind: SocketAddr = env_or("SIGNET_BIND", "0.0.0.0:8443".parse().unwrap())?;
        let db_path = PathBuf::from(env_or("SIGNET_DB", "signet.db".to_string())?);
        let tls_cert = PathBuf::from(env_required("SIGNET_TLS_CERT")?);
        let tls_key = PathBuf::from(env_required("SIGNET_TLS_KEY")?);
        let client_ca = PathBuf::from(env_required("SIGNET_CLIENT_CA")?);

        let mut kek_raw = env_required("SIGNET_KEK")?;
        let kek_result = Kek::from_encoded(&kek_raw);
        // Wipe the encoded KEK from our heap copy as soon as it is parsed,
        // regardless of whether parsing succeeded, so the raw key material does
        // not linger in process memory.
        kek_raw.zeroize();
        // Remove the KEK from the process environment so it is not readable via
        // /proc/<pid>/environ, inherited by any child process, or surfaced by a
        // crash dump that walks the environment block. The in-memory `Kek` is
        // the only remaining copy and is itself zeroized on drop.
        //
        // SAFETY: `remove_var` is sound here because config loading happens once
        // at startup, before any worker threads that might read the environment
        // are spawned (see `main::run`), so there is no concurrent env access.
        std::env::remove_var("SIGNET_KEK");
        let kek = kek_result.map_err(|e| format!("SIGNET_KEK is invalid: {e}"))?;

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

        let info_prefix =
            validate_info_prefix(env_or("SIGNET_INFO_PREFIX", DEFAULT_INFO_PREFIX.to_string())?)?;

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
            info_prefix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefix_preserves_freedink_wire() {
        // Unset SIGNET_INFO_PREFIX => the FreedInk default, byte-for-byte.
        assert_eq!(
            validate_info_prefix(DEFAULT_INFO_PREFIX.to_string()).unwrap(),
            "freedink-vote"
        );
    }

    #[test]
    fn accepts_custom_prefix() {
        // The whole allowed charset: letters, digits, '-', '_', '.'.
        for ok in ["deforum-ban", "freedink-vote", "app_ban.v2", "ABC123"] {
            assert_eq!(validate_info_prefix(ok.to_string()).unwrap(), ok);
        }
    }

    #[test]
    fn rejects_empty_prefix() {
        assert!(validate_info_prefix(String::new()).is_err());
    }

    #[test]
    fn rejects_prefix_with_colon() {
        // A colon would change the metadata byte layout (`a:b:<version>`); the
        // separator is inserted by version_info, never by the operator.
        assert!(validate_info_prefix("deforum-ban:".to_string()).is_err());
        assert!(validate_info_prefix("a:b".to_string()).is_err());
    }

    #[test]
    fn rejects_whitespace() {
        // The classic silent-mismatch trap: stray space from a .env file, in any
        // position. Surrounding, internal, and newline whitespace all rejected.
        assert!(validate_info_prefix("deforum-ban ".to_string()).is_err());
        assert!(validate_info_prefix(" deforum-ban".to_string()).is_err());
        assert!(validate_info_prefix("deforum ban".to_string()).is_err());
        assert!(validate_info_prefix("deforum-ban\n".to_string()).is_err());
    }

    #[test]
    fn rejects_control_characters() {
        assert!(validate_info_prefix("deforum\tban".to_string()).is_err());
    }

    #[test]
    fn rejects_non_ascii() {
        // Non-ASCII is a normalization footgun: the same-looking prefix can be
        // different UTF-8 bytes on the signer vs. the client/verifier host.
        assert!(validate_info_prefix("déforum-ban".to_string()).is_err());
        assert!(validate_info_prefix("deforum-ban\u{200b}".to_string()).is_err());
    }

    #[test]
    fn rejects_overlong_prefix() {
        assert!(validate_info_prefix("x".repeat(65)).is_err());
        assert!(validate_info_prefix("x".repeat(64)).is_ok());
    }
}
