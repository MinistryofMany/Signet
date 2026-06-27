//! Shared application state handed to every handler.

use crate::db::Db;
use crate::keygen::KeygenService;
use crate::keystore::Kek;
use crate::ratelimit::{KeyRateLimiter, RateLimiter};
use std::sync::Arc;

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
}
