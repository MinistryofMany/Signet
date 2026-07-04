//! Shared application state handed to every handler.

use crate::db::Db;
use crate::keygen::KeygenService;
use crate::keystore::Kek;
use crate::prf::PrfKeys;
use crate::ratelimit::{KeyRateLimiter, RateLimiter};
use std::collections::BTreeSet;
use std::sync::Arc;

/// State for the PRF/dedup surface. Present only when the fail-closed boot
/// policy enabled it (service keys initialized, non-empty allow-list, public
/// key pin verified); `None` means the `/prf/*` and `/dedup/*` routes are not
/// even mounted.
pub struct PrfState {
    pub keys: PrfKeys,
    /// The `SIGNET_PRF_CLIENT_IDS` allow-list, checked INSIDE each PRF/dedup
    /// handler (per-route, fail-closed — mirroring the `is_admin()` gate).
    pub allowed_client_ids: BTreeSet<String>,
    /// The PRF surface's own rate-limit bucket (separate from /sign + /key*).
    pub rate_limiter: KeyRateLimiter,
}

pub struct AppState {
    /// Shared with [`KeygenService`] so handlers and the keygen worker pool use
    /// the same SQLite connection (one write-serialized connection behind a
    /// mutex), never two connections to the same file.
    pub db: Arc<Db>,
    pub kek: Kek,
    pub rate_limiter: RateLimiter,
    /// Rate limiter for the `/key*` endpoints (per-client-identity + global).
    pub key_rate_limiter: KeyRateLimiter,
    /// Async key-generation worker pool + in-flight dedup (audit H1).
    pub keygen: KeygenService,
    pub auto_create_keys: bool,
    pub key_bits: usize,
    /// PRF/dedup surface state; `None` = surface disabled (routes unmounted).
    pub prf: Option<PrfState>,
}
