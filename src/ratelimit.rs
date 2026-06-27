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
use std::time::{SystemTime, UNIX_EPOCH};

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
}
