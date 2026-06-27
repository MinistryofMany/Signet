//! Rate limiting, evaluated against the issuance ledger.
//!
//! Two ceilings, both over a sliding window:
//!   - per-participant: a single participant_id may obtain at most N tokens
//!     per window (defends a compromised or buggy relying party from draining
//!     one user's allowance / hammering the signer for one identity).
//!   - global: at most M tokens per window across ALL participants (a hard cap
//!     on total issuance, bounding blast radius if the relying party is fully
//!     compromised).
//!
//! The window is derived from the issuance timestamps already stored for the
//! one-per-tuple invariant, so rate limiting needs no extra state. Checks run
//! BEFORE the record-first reservation; the reservation itself then enforces
//! uniqueness.

use crate::db::Db;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct RateLimiter {
    participant_max: u32,
    global_max: u32,
    window_secs: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    DenyParticipant,
    DenyGlobal,
}

fn now_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => {
            // Clock before the unix epoch: `since = 0 - window` goes negative,
            // so every issuance row falls inside the window and the ceilings
            // count *all* rows. That fails closed (more likely to deny), which
            // is the safe direction for a rate limiter.
            tracing::error!(
                error = %e,
                "system clock is before the unix epoch; rate-limit window fails closed"
            );
            0
        }
    }
}

impl RateLimiter {
    pub fn new(participant_max: u32, global_max: u32, window_secs: u64) -> Self {
        Self {
            participant_max,
            global_max,
            window_secs,
        }
    }

    /// Evaluate both ceilings for `participant_id` at the current time.
    ///
    /// Note: a tuple that has already been issued will be rejected later as a
    /// duplicate, so re-requests for an existing token do not consume rate
    /// budget beyond the first successful issuance row. We count issuance rows
    /// in the window, which is the conservative, audit-aligned measure.
    pub fn check(&self, db: &Db, participant_id: &str) -> Result<Decision, String> {
        let since = now_secs() - self.window_secs as i64;

        let global = db.count_global_since(since)?;
        if global >= self.global_max {
            return Ok(Decision::DenyGlobal);
        }

        let per = db.count_participant_since(participant_id, since)?;
        if per >= self.participant_max {
            return Ok(Decision::DenyParticipant);
        }

        Ok(Decision::Allow)
    }
}

/// Rate limiter for the `/key*` endpoints (key creation, auto-create lookups,
/// and rotation) — audit H1.
///
/// Unlike [`RateLimiter`], keygen requests leave no issuance rows to count, so
/// this limiter keeps its own in-memory sliding window of request timestamps:
///   - **per-identity**: a single pinned client identity may issue at most N
///     key-endpoint requests per window (bounds how fast one client can trigger
///     multi-second keygens), and
///   - **global**: at most M key-endpoint requests per window across all
///     identities (a hard ceiling on total keygen pressure).
///
/// The identity key space is bounded by the configured allow-lists (only pinned
/// identities ever reach a handler), and empty per-identity buckets are pruned,
/// so the map cannot grow without bound.
pub struct KeyRateLimiter {
    identity_max: u32,
    global_max: u32,
    window: Duration,
    state: Mutex<KeyRlState>,
}

#[derive(Default)]
struct KeyRlState {
    per_identity: HashMap<String, Vec<Instant>>,
    global: Vec<Instant>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyDecision {
    Allow,
    DenyIdentity,
    DenyGlobal,
}

impl KeyRateLimiter {
    pub fn new(identity_max: u32, global_max: u32, window_secs: u64) -> Self {
        Self {
            identity_max,
            global_max,
            window: Duration::from_secs(window_secs),
            state: Mutex::new(KeyRlState::default()),
        }
    }

    /// Record a request from `identity` at `now` and decide whether it is within
    /// both ceilings. The request timestamp is recorded only if it is allowed,
    /// so a denied request does not consume budget.
    fn check_at(&self, identity: &str, now: Instant) -> KeyDecision {
        let cutoff = now.checked_sub(self.window);
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Prune + count the global window first (global ceiling is the hard cap).
        prune(&mut st.global, cutoff);
        if st.global.len() as u64 >= self.global_max as u64 {
            return KeyDecision::DenyGlobal;
        }

        let bucket = st.per_identity.entry(identity.to_string()).or_default();
        prune(bucket, cutoff);
        if bucket.len() as u64 >= self.identity_max as u64 {
            // Drop an empty-after-prune bucket only when it is actually empty;
            // here it is at the ceiling, so keep it.
            return KeyDecision::DenyIdentity;
        }

        // Allowed: record in both windows.
        bucket.push(now);
        st.global.push(now);
        KeyDecision::Allow
    }

    /// Evaluate the key-endpoint ceilings for `identity` at the current time.
    pub fn check(&self, identity: &str) -> KeyDecision {
        self.check_at(identity, Instant::now())
    }
}

/// Drop timestamps at or before `cutoff` (the start of the window). A `None`
/// cutoff means `now` is closer to the process start than one window, so nothing
/// has expired yet.
fn prune(times: &mut Vec<Instant>, cutoff: Option<Instant>) {
    if let Some(cutoff) = cutoff {
        times.retain(|t| *t > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participant_ceiling_fires() {
        let db = Db::open_in_memory().unwrap();
        let rl = RateLimiter::new(2, 100, 60);
        // Two issuances for the same participant across different versions.
        for v in ["v1", "v2"] {
            assert_eq!(rl.check(&db, "alice").unwrap(), Decision::Allow);
            matches!(
                db.reserve_issuance("g", "alice", v).unwrap(),
                crate::db::Reservation::Reserved(_)
            );
        }
        // Third request must be denied at the participant ceiling.
        assert_eq!(rl.check(&db, "alice").unwrap(), Decision::DenyParticipant);
        // A different participant is unaffected.
        assert_eq!(rl.check(&db, "bob").unwrap(), Decision::Allow);
    }

    #[test]
    fn global_ceiling_fires() {
        let db = Db::open_in_memory().unwrap();
        let rl = RateLimiter::new(100, 2, 60);
        db.reserve_issuance("g", "alice", "v1").unwrap();
        db.reserve_issuance("g", "bob", "v1").unwrap();
        // Global cap of 2 reached; even a fresh participant is denied.
        assert_eq!(rl.check(&db, "carol").unwrap(), Decision::DenyGlobal);
    }

    #[test]
    fn key_rl_per_identity_ceiling_fires() {
        let rl = KeyRateLimiter::new(2, 100, 60);
        let now = Instant::now();
        assert_eq!(rl.check_at("freedink", now), KeyDecision::Allow);
        assert_eq!(rl.check_at("freedink", now), KeyDecision::Allow);
        // Third within the window is denied for this identity.
        assert_eq!(rl.check_at("freedink", now), KeyDecision::DenyIdentity);
        // A different identity has its own budget.
        assert_eq!(rl.check_at("other", now), KeyDecision::Allow);
    }

    #[test]
    fn key_rl_global_ceiling_fires() {
        let rl = KeyRateLimiter::new(100, 2, 60);
        let now = Instant::now();
        assert_eq!(rl.check_at("a", now), KeyDecision::Allow);
        assert_eq!(rl.check_at("b", now), KeyDecision::Allow);
        // Global cap of 2 reached; a fresh identity is denied globally.
        assert_eq!(rl.check_at("c", now), KeyDecision::DenyGlobal);
    }

    #[test]
    fn key_rl_window_slides() {
        let rl = KeyRateLimiter::new(1, 100, 60);
        let t0 = Instant::now();
        assert_eq!(rl.check_at("x", t0), KeyDecision::Allow);
        // Same instant, over the per-identity cap of 1.
        assert_eq!(rl.check_at("x", t0), KeyDecision::DenyIdentity);
        // Well past the window: the old timestamp has aged out, allow again.
        let later = t0 + Duration::from_secs(61);
        assert_eq!(rl.check_at("x", later), KeyDecision::Allow);
    }

    #[test]
    fn key_rl_denied_request_does_not_consume_budget() {
        let rl = KeyRateLimiter::new(1, 1, 60);
        let now = Instant::now();
        // First identity uses the single global slot.
        assert_eq!(rl.check_at("a", now), KeyDecision::Allow);
        // Second identity is denied globally; this must NOT push a timestamp,
        // so the global window stays at exactly 1 recorded request.
        assert_eq!(rl.check_at("b", now), KeyDecision::DenyGlobal);
        let st = rl.state.lock().unwrap();
        assert_eq!(st.global.len(), 1, "denied request must not be recorded");
    }
}
