//! SQLite persistence: group keys (encrypted private key at rest) and the
//! issuance ledger that enforces one-signature-per-(group, participant,
//! version) and feeds rate limiting / audit.
//!
//! Concurrency: a single write-serialized connection behind a mutex is the
//! simplest race-safe design for this low-throughput service. The uniqueness
//! invariant is additionally backed by a UNIQUE index, so even if the
//! application logic were bypassed the database refuses a second issuance.
//!
//! NEVER stored: the unblinded nonce, the blinded message, or any signature.
//! The issuance row holds only (group_id, participant_id, version_id, ts).

use crate::keystore::Kek;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Db {
    conn: Mutex<Connection>,
}

/// Outcome of attempting to reserve an issuance slot.
pub enum Reservation {
    /// The slot was reserved; proceed to sign. Carries the row id.
    Reserved(i64),
    /// A signature was already issued for this tuple.
    AlreadyIssued,
}

pub struct GroupKey {
    pub key_id: i64,
    pub spki_der: Vec<u8>,
    /// Encrypted PKCS#8 blob (ciphertext at rest).
    pub sealed_pkcs8: Vec<u8>,
}

/// Current unix time in seconds.
///
/// `SystemTime::now()` can only be before the unix epoch if the host clock is
/// grossly misconfigured (set to before 1970). That should never happen on a
/// real deployment, but if it does we must NOT silently store a `0` timestamp:
/// a `0` issued_at would sit forever outside every rate-limit window and skew
/// the audit ledger. We log loudly and fall back to `0` only as a last resort
/// (with `0`, the rate-limit window math `now - window` goes negative, which
/// counts *all* rows and therefore fails closed on the global ceiling).
fn now_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => {
            tracing::error!(
                error = %e,
                "system clock is before the unix epoch; using 0 (rate limiting fails closed)"
            );
            0
        }
    }
}

/// Convert a SQLite `COUNT(*)` (`i64`, always `>= 0`) to `u32`, saturating
/// instead of wrapping. A negative count is impossible from `COUNT(*)`, and a
/// count above `u32::MAX` would only arise from an absurd number of issuance
/// rows; in either pathological case, saturating to `u32::MAX` makes every rate
/// limit deny (fails closed) rather than wrapping to a small value that would
/// fail open.
fn saturating_count_to_u32(count: i64) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, String> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| e.to_string())?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| e.to_string())?;
        conn.pragma_update(None, "busy_timeout", 5000)
            .map_err(|e| e.to_string())?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS group_keys (
                key_id        INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id      TEXT NOT NULL,
                spki_der      BLOB NOT NULL,
                sealed_pkcs8  BLOB NOT NULL,
                created_at    INTEGER NOT NULL,
                retired_at    INTEGER
            );
            -- At most one ACTIVE (non-retired) key per group.
            CREATE UNIQUE INDEX IF NOT EXISTS idx_group_keys_active
                ON group_keys(group_id) WHERE retired_at IS NULL;

            CREATE TABLE IF NOT EXISTS issuances (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id       TEXT NOT NULL,
                participant_id TEXT NOT NULL,
                version_id     TEXT NOT NULL,
                issued_at      INTEGER NOT NULL
            );
            -- Hard cap: one signature per (group, participant, version).
            CREATE UNIQUE INDEX IF NOT EXISTS idx_issuance_unique
                ON issuances(group_id, participant_id, version_id);
            -- Rate-limit lookups by participant and time.
            CREATE INDEX IF NOT EXISTS idx_issuance_participant_time
                ON issuances(participant_id, issued_at);
            CREATE INDEX IF NOT EXISTS idx_issuance_time
                ON issuances(issued_at);
            "#,
        )
        .map_err(|e| e.to_string())?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    /// Lock the connection, recovering from poisoning.
    ///
    /// The binary builds with `panic = "abort"`, so an in-lock panic would take
    /// the whole process down before poisoning could matter. But the library is
    /// also linked into the test harness (which unwinds) and into any future
    /// build that does not abort. Recovering the inner guard rather than
    /// `unwrap()`-ing means a single panic while holding the lock cannot
    /// cascade into a poison-panic on every subsequent DB call. The SQLite
    /// connection has no in-memory invariants that a mid-statement panic could
    /// corrupt (each method runs one statement / one transaction), so the
    /// recovered guard is safe to use.
    fn lock_conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Fetch the active (non-retired) key for a group, if any.
    pub fn active_key(&self, group_id: &str) -> Result<Option<GroupKey>, String> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT key_id, spki_der, sealed_pkcs8 FROM group_keys \
             WHERE group_id = ?1 AND retired_at IS NULL",
            params![group_id],
            |row| {
                Ok(GroupKey {
                    key_id: row.get(0)?,
                    spki_der: row.get(1)?,
                    sealed_pkcs8: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    /// Insert a new active key. Fails if one already exists (UNIQUE index).
    pub fn insert_key(
        &self,
        group_id: &str,
        spki_der: &[u8],
        sealed_pkcs8: &[u8],
    ) -> Result<i64, String> {
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO group_keys (group_id, spki_der, sealed_pkcs8, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![group_id, spki_der, sealed_pkcs8, now_secs()],
        )
        .map_err(|e| e.to_string())?;
        Ok(conn.last_insert_rowid())
    }

    /// Atomically retire the current active key and insert a new one,
    /// returning the new key id. Both happen in one transaction so the
    /// at-most-one-active invariant is never transiently violated.
    pub fn rotate_key(
        &self,
        group_id: &str,
        spki_der: &[u8],
        sealed_pkcs8: &[u8],
    ) -> Result<i64, String> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE group_keys SET retired_at = ?1 WHERE group_id = ?2 AND retired_at IS NULL",
            params![now_secs(), group_id],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO group_keys (group_id, spki_der, sealed_pkcs8, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![group_id, spki_der, sealed_pkcs8, now_secs()],
        )
        .map_err(|e| e.to_string())?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(|e| e.to_string())?;
        Ok(id)
    }

    /// Record-first reservation of an issuance slot. Inserts the issuance row
    /// BEFORE signing; the UNIQUE index makes a concurrent double-issue fail
    /// here, closing the check-then-act race. Returns AlreadyIssued on conflict.
    pub fn reserve_issuance(
        &self,
        group_id: &str,
        participant_id: &str,
        version_id: &str,
    ) -> Result<Reservation, String> {
        let conn = self.lock_conn();
        let res = conn.execute(
            "INSERT INTO issuances (group_id, participant_id, version_id, issued_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![group_id, participant_id, version_id, now_secs()],
        );
        match res {
            Ok(_) => Ok(Reservation::Reserved(conn.last_insert_rowid())),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Ok(Reservation::AlreadyIssued)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Delete a reservation row by id. Used to roll back if signing fails after
    /// the slot was reserved, so a transient signing error does not permanently
    /// burn the participant's one allowed token.
    pub fn delete_issuance(&self, id: i64) -> Result<(), String> {
        let conn = self.lock_conn();
        conn.execute("DELETE FROM issuances WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Count issuances for a participant since `since` (unix secs).
    pub fn count_participant_since(
        &self,
        participant_id: &str,
        since: i64,
    ) -> Result<u32, String> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT COUNT(*) FROM issuances WHERE participant_id = ?1 AND issued_at >= ?2",
            params![participant_id, since],
            |row| row.get::<_, i64>(0),
        )
        .map(saturating_count_to_u32)
        .map_err(|e| e.to_string())
    }

    /// Count all issuances since `since` (unix secs) for the global ceiling.
    pub fn count_global_since(&self, since: i64) -> Result<u32, String> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT COUNT(*) FROM issuances WHERE issued_at >= ?1",
            params![since],
            |row| row.get::<_, i64>(0),
        )
        .map(saturating_count_to_u32)
        .map_err(|e| e.to_string())
    }

    /// Assert that no plaintext PKCS#8 is present in any stored key blob. Used
    /// by the at-rest test. A real PKCS#8 RSA private key DER begins with the
    /// SEQUENCE/INTEGER(version=0) prefix `30 82 .. .. 02 01 00`; AES-GCM
    /// ciphertext will not start with our blob version byte followed by that.
    #[cfg(test)]
    pub fn raw_sealed_blobs(&self) -> Result<Vec<Vec<u8>>, String> {
        let conn = self.lock_conn();
        let mut stmt = conn
            .prepare("SELECT sealed_pkcs8 FROM group_keys")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }
}

/// Get-or-create the active key for a group, encrypting the private key at rest.
/// Returns the decrypted PKCS#8 and the SPKI. The decrypted key lives only in
/// the returned value's lifetime on the caller's stack.
pub fn get_or_create_key(
    db: &Db,
    kek: &Kek,
    group_id: &str,
    bits: usize,
    auto_create: bool,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if let Some(k) = db.active_key(group_id)? {
        let pkcs8 = kek.open(group_id, k.key_id, &k.sealed_pkcs8)?;
        return Ok((pkcs8, k.spki_der));
    }
    if !auto_create {
        return Err("no key".to_string());
    }
    create_key(db, kek, group_id, bits)
}

/// Create a fresh active key for a group and persist it (encrypted).
pub fn create_key(
    db: &Db,
    kek: &Kek,
    group_id: &str,
    bits: usize,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let generated = crate::crypto::generate_group_key(bits)?;
    // The sealed blob binds key_id as AES-GCM associated data, but the
    // auto-increment key_id is only known after the row is inserted. So: insert
    // with a placeholder seal (bound to id 0), learn the real key_id, reseal
    // bound to that id, and update the row in place. The placeholder never
    // leaves the DB except as the immediately-overwritten value.
    let placeholder = kek.seal(group_id, 0, &generated.pkcs8_der)?;
    let key_id = db.insert_key(group_id, &generated.spki_der, &placeholder)?;
    let sealed = kek.seal(group_id, key_id, &generated.pkcs8_der)?;
    db.update_sealed(key_id, &sealed)?;
    Ok((generated.pkcs8_der, generated.spki_der))
}

/// Rotate a group's key, persisting the new one encrypted at rest.
pub fn rotate_key(
    db: &Db,
    kek: &Kek,
    group_id: &str,
    bits: usize,
) -> Result<Vec<u8>, String> {
    let generated = crate::crypto::generate_group_key(bits)?;
    let placeholder = kek.seal(group_id, 0, &generated.pkcs8_der)?;
    let key_id = db.rotate_key(group_id, &generated.spki_der, &placeholder)?;
    let sealed = kek.seal(group_id, key_id, &generated.pkcs8_der)?;
    db.update_sealed(key_id, &sealed)?;
    Ok(generated.spki_der)
}

impl Db {
    /// Update the sealed blob for a key id (used after learning the auto id).
    pub fn update_sealed(&self, key_id: i64, sealed_pkcs8: &[u8]) -> Result<(), String> {
        let conn = self.lock_conn();
        conn.execute(
            "UPDATE group_keys SET sealed_pkcs8 = ?1 WHERE key_id = ?2",
            params![sealed_pkcs8, key_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}
