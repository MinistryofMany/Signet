//! Shared application state handed to every handler.

use crate::db::Db;
use crate::keystore::Kek;
use crate::ratelimit::RateLimiter;

pub struct AppState {
    pub db: Db,
    pub kek: Kek,
    pub rate_limiter: RateLimiter,
    pub auto_create_keys: bool,
    pub key_bits: usize,
}
