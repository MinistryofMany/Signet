//! SQLite persistence: group keys (encrypted private key at rest), the
//! issuance ledger that enforces one-signature-per-(group, participant,
//! version) and feeds rate limiting / audit, plus the PRF-surface tables —
//! `service_keys` (KEK-sealed service key material) and `dedup_entries`
//! (the credential dedup ledger, UNIQUE over the deterministic VOPRF output).
//!
//! Concurrency: a single write-serialized connection behind a mutex is the
//! simplest race-safe design for this low-throughput service. The uniqueness
//! invariants are additionally backed by UNIQUE indexes, so even if the
//! application logic were bypassed the database refuses a second issuance /
//! a second registration of the same dedup value.
//!
//! NEVER stored: the unblinded nonce, the blinded message, or any signature.
//! The issuance row holds only (group_id, participant_id, version_id, ts).
//! The dedup ledger stores only (entry_ref, value, owner_tag, badge_type, ts):
//! `value` is a PRF output (never the raw anchor) and `owner_tag` is an opaque
//! per-user handle minted by Minister (never a raw Minister userId).

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

/// A row in the credential dedup ledger.
pub struct DedupEntry {
    /// Opaque 16-byte random primary key; the handle Minister stores as
    /// `Badge.nullifierRef`.
    pub entry_ref: Vec<u8>,
    /// The deterministic stage-1 VOPRF output (`N_dedup`, 64 bytes). UNIQUE —
    /// byte equality of this column IS the dedup comparison.
    pub value: Vec<u8>,
    /// Opaque per-user owner handle minted by Minister (never a raw userId).
    pub owner_tag: String,
    pub badge_type: String,
}

/// Outcome of a record-first dedup registration.
pub enum DedupRegister {
    /// The value was new; a fresh entry was recorded.
    Registered { entry_ref: Vec<u8> },
    /// The value already exists and is owned by the SAME owner tag
    /// (re-issue / renewal); the existing entry ref is returned.
    AlreadyYours { entry_ref: Vec<u8> },
    /// The value already exists under a DIFFERENT owner tag: refused
    /// (one-credential-one-account).
    Taken,
}

/// Outcome of an owner-checked release.
pub enum DedupRelease {
    Released,
    /// No such entry — treated as success by callers (idempotent retry).
    NotFound,
    /// The entry exists but is owned by a different tag: refused.
    OwnerMismatch,
}

/// Outcome of an owner-checked, all-or-nothing batch reassign.
pub enum DedupReassign {
    /// Every listed ref is now owned by the target tag; `moved` counts the
    /// rows whose owner actually changed in this call (refs already owned by
    /// the target are idempotent no-ops).
    Reassigned { moved: usize },
    /// A listed ref does not exist; nothing was changed.
    NotFound,
    /// A listed ref is owned by neither the source nor the target tag;
    /// nothing was changed.
    OwnerMismatch,
}

/// Constant-time owner-handle equality for the dedup ledger's authorization
/// compares (register/release/reassign classification and the disclose owner
/// check). Handles are 128-bit random values minted by Minister and only
/// PRF-allow-listed callers reach these paths, so a remote timing oracle is
/// already impractical — but this is a crypto-core authorization compare, so
/// it does not short-circuit on content. The length check inside `ct_eq` is
/// the only data-dependent branch (handle length is not secret).
pub(crate) fn owner_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
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

            -- PRF-surface service keys, KEK-sealed (AES-GCM, AAD-bound to the
            -- purpose string). NEVER plaintext key material.
            CREATE TABLE IF NOT EXISTS service_keys (
                purpose     TEXT PRIMARY KEY,
                sealed      BLOB NOT NULL,
                created_at  INTEGER NOT NULL
            );

            -- Credential dedup ledger: UNIQUE(value) is the dedup comparison
            -- (byte equality of deterministic VOPRF outputs). entry_ref is an
            -- opaque random handle; owner_tag an opaque per-user handle.
            CREATE TABLE IF NOT EXISTS dedup_entries (
                entry_ref   BLOB PRIMARY KEY,
                value       BLOB NOT NULL UNIQUE,
                owner_tag   TEXT NOT NULL,
                badge_type  TEXT NOT NULL,
                created_at  INTEGER NOT NULL
            );
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

    /// Insert a fresh active key, sealing its private blob under the real
    /// auto-increment `key_id` ATOMICALLY. The sealed blob is AES-GCM AAD-bound
    /// to `key_id`, which is only known once the row is inserted, so this inserts
    /// the row with a transient empty blob, calls `seal(key_id)` to produce the
    /// real ciphertext, and writes it back - all inside ONE transaction. A crash
    /// or a `seal` failure rolls the whole thing back, so a group can never be
    /// left with an "active" row whose stored blob is bound to the wrong id and
    /// can therefore never be decrypted (audit L4). Fails if an active key
    /// already exists (partial UNIQUE index).
    pub fn insert_key_sealed<F>(
        &self,
        group_id: &str,
        spki_der: &[u8],
        seal: F,
    ) -> Result<i64, String>
    where
        F: FnOnce(i64) -> Result<Vec<u8>, String>,
    {
        let mut conn = self.lock_conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let key_id = insert_active_key_resealed(&tx, group_id, spki_der, seal)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(key_id)
    }

    /// Atomically retire the current active key and insert a fresh one, sealing
    /// the new private blob under its assigned id - ALL in one transaction. A
    /// crash never leaves either a doubly-active group (the at-most-one-active
    /// invariant holds transiently) or an unopenable active key (audit L4).
    /// Returns the new key id.
    pub fn rotate_key_sealed<F>(
        &self,
        group_id: &str,
        spki_der: &[u8],
        seal: F,
    ) -> Result<i64, String>
    where
        F: FnOnce(i64) -> Result<Vec<u8>, String>,
    {
        let mut conn = self.lock_conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE group_keys SET retired_at = ?1 WHERE group_id = ?2 AND retired_at IS NULL",
            params![now_secs(), group_id],
        )
        .map_err(|e| e.to_string())?;
        let key_id = insert_active_key_resealed(&tx, group_id, spki_der, seal)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(key_id)
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
    pub fn count_participant_since(&self, participant_id: &str, since: i64) -> Result<u32, String> {
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

    // -----------------------------------------------------------------------
    // PRF surface: service_keys
    // -----------------------------------------------------------------------

    /// Fetch the sealed blob for a service-key purpose, if present.
    pub fn get_service_key(&self, purpose: &str) -> Result<Option<Vec<u8>>, String> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT sealed FROM service_keys WHERE purpose = ?1",
            params![purpose],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    /// Insert a sealed service key. Returns `false` (and stores nothing) if a
    /// row for this purpose already exists — service keys are never silently
    /// overwritten (key-fork prevention).
    pub fn insert_service_key(&self, purpose: &str, sealed: &[u8]) -> Result<bool, String> {
        let conn = self.lock_conn();
        let res = conn.execute(
            "INSERT INTO service_keys (purpose, sealed, created_at) VALUES (?1, ?2, ?3)",
            params![purpose, sealed, now_secs()],
        );
        match res {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Ok(false)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    // -----------------------------------------------------------------------
    // PRF surface: dedup ledger
    // -----------------------------------------------------------------------

    /// Record-first dedup registration, mirroring [`Db::reserve_issuance`]:
    /// INSERT first and let `UNIQUE(value)` decide the race. On conflict the
    /// existing row is fetched UNDER THE SAME CONNECTION LOCK and classified
    /// by owner tag, so a concurrent register/release cannot interleave
    /// between the insert attempt and the classification.
    pub fn register_dedup(
        &self,
        entry_ref: &[u8],
        value: &[u8],
        owner_tag: &str,
        badge_type: &str,
    ) -> Result<DedupRegister, String> {
        let conn = self.lock_conn();
        let res = conn.execute(
            "INSERT INTO dedup_entries (entry_ref, value, owner_tag, badge_type, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![entry_ref, value, owner_tag, badge_type, now_secs()],
        );
        match res {
            Ok(_) => Ok(DedupRegister::Registered {
                entry_ref: entry_ref.to_vec(),
            }),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                // UNIQUE(value) fired (an entry_ref PK collision is a 2^-128
                // event; the None arm below fails it closed as an internal
                // error rather than guessing).
                let existing = conn
                    .query_row(
                        "SELECT entry_ref, owner_tag FROM dedup_entries WHERE value = ?1",
                        params![value],
                        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()
                    .map_err(|e| e.to_string())?;
                match existing {
                    Some((existing_ref, existing_owner)) if owner_eq(&existing_owner, owner_tag) => {
                        Ok(DedupRegister::AlreadyYours {
                            entry_ref: existing_ref,
                        })
                    }
                    Some(_) => Ok(DedupRegister::Taken),
                    None => Err(
                        "dedup register hit a constraint but no row exists for the value \
                         (entry_ref collision?)"
                            .to_string(),
                    ),
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Fetch a dedup entry by its opaque ref.
    pub fn dedup_entry_by_ref(&self, entry_ref: &[u8]) -> Result<Option<DedupEntry>, String> {
        let conn = self.lock_conn();
        conn.query_row(
            "SELECT entry_ref, value, owner_tag, badge_type FROM dedup_entries \
             WHERE entry_ref = ?1",
            params![entry_ref],
            |row| {
                Ok(DedupEntry {
                    entry_ref: row.get(0)?,
                    value: row.get(1)?,
                    owner_tag: row.get(2)?,
                    badge_type: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    /// Owner-checked release. The lookup and delete run under one connection
    /// lock, so the owner check cannot race a concurrent re-registration.
    pub fn release_dedup(&self, entry_ref: &[u8], owner_tag: &str) -> Result<DedupRelease, String> {
        let conn = self.lock_conn();
        let existing = conn
            .query_row(
                "SELECT owner_tag FROM dedup_entries WHERE entry_ref = ?1",
                params![entry_ref],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        match existing {
            None => Ok(DedupRelease::NotFound),
            Some(owner) if !owner_eq(&owner, owner_tag) => Ok(DedupRelease::OwnerMismatch),
            Some(_) => {
                conn.execute(
                    "DELETE FROM dedup_entries WHERE entry_ref = ?1",
                    params![entry_ref],
                )
                .map_err(|e| e.to_string())?;
                Ok(DedupRelease::Released)
            }
        }
    }

    /// Owner-checked batch reassign over an EXPLICIT ref list (merge / reverse
    /// merge), all-or-nothing in one transaction. Each ref must be owned by
    /// `from` (moved) or already by `to` (idempotent-retry no-op); any other
    /// state rolls the whole batch back.
    pub fn reassign_dedup(
        &self,
        entry_refs: &[Vec<u8>],
        from: &str,
        to: &str,
    ) -> Result<DedupReassign, String> {
        let mut conn = self.lock_conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let mut moved = 0usize;
        for entry_ref in entry_refs {
            let owner = tx
                .query_row(
                    "SELECT owner_tag FROM dedup_entries WHERE entry_ref = ?1",
                    params![entry_ref],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            match owner {
                None => return Ok(DedupReassign::NotFound), // tx drops -> rollback
                Some(owner) if owner_eq(&owner, from) => {
                    tx.execute(
                        "UPDATE dedup_entries SET owner_tag = ?1 WHERE entry_ref = ?2",
                        params![to, entry_ref],
                    )
                    .map_err(|e| e.to_string())?;
                    moved += 1;
                }
                Some(owner) if owner_eq(&owner, to) => {} // already moved (retry) — no-op
                Some(_) => return Ok(DedupReassign::OwnerMismatch), // rollback
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(DedupReassign::Reassigned { moved })
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

/// Within `tx`: insert an active-key row with a transient empty sealed blob,
/// seal the private key under the assigned auto-increment id, and write it back.
/// Returns the new key id. The blob's AES-GCM AAD binds the real key_id, which
/// is only known after the insert, so the insert + reseal + update must live in
/// one transaction (the caller commits it); any error here leaves the whole
/// transaction to roll back, so no half-sealed / unopenable row is ever
/// persisted (audit L4). The empty placeholder blob exists only inside the
/// uncommitted transaction and is always overwritten before commit.
fn insert_active_key_resealed<F>(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    spki_der: &[u8],
    seal: F,
) -> Result<i64, String>
where
    F: FnOnce(i64) -> Result<Vec<u8>, String>,
{
    tx.execute(
        "INSERT INTO group_keys (group_id, spki_der, sealed_pkcs8, created_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![group_id, spki_der, Vec::<u8>::new(), now_secs()],
    )
    .map_err(|e| e.to_string())?;
    let key_id = tx.last_insert_rowid();
    let sealed = seal(key_id)?;
    let updated = tx
        .execute(
            "UPDATE group_keys SET sealed_pkcs8 = ?1 WHERE key_id = ?2",
            params![sealed, key_id],
        )
        .map_err(|e| e.to_string())?;
    if updated != 1 {
        return Err(format!(
            "reseal updated {updated} rows for key_id {key_id} (expected 1)"
        ));
    }
    Ok(key_id)
}

/// Create a fresh active key for a group and persist it (encrypted, atomically).
pub fn create_key(
    db: &Db,
    kek: &Kek,
    group_id: &str,
    bits: usize,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let generated = crate::crypto::generate_group_key(bits)?;
    db.insert_key_sealed(group_id, &generated.spki_der, |key_id| {
        kek.seal(group_id, key_id, &generated.pkcs8_der)
    })?;
    Ok((generated.pkcs8_der, generated.spki_der))
}

/// Rotate a group's key, persisting the new one encrypted at rest (atomically).
pub fn rotate_key(db: &Db, kek: &Kek, group_id: &str, bits: usize) -> Result<Vec<u8>, String> {
    let generated = crate::crypto::generate_group_key(bits)?;
    db.rotate_key_sealed(group_id, &generated.spki_der, |key_id| {
        kek.seal(group_id, key_id, &generated.pkcs8_der)
    })?;
    Ok(generated.spki_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> Kek {
        Kek::from_encoded(&hex::encode([0x5au8; 32])).unwrap()
    }

    #[test]
    fn insert_key_sealed_rolls_back_when_reseal_fails() {
        // Models a mid-op failure in the (formerly non-atomic) insert -> reseal
        // window. It MUST leave no row behind - a group must never end up with an
        // "active" key whose stored blob is bound to the wrong id and can never be
        // decrypted (audit L4).
        let db = Db::open_in_memory().unwrap();
        let r = db.insert_key_sealed("g1", b"spki-der", |_key_id| Err("seal boom".to_string()));
        assert!(r.is_err());
        assert!(
            db.active_key("g1").unwrap().is_none(),
            "a failed reseal must roll the inserted row back (no bricked active key)"
        );
    }

    #[test]
    fn insert_key_sealed_binds_the_blob_to_the_assigned_key_id() {
        // On success the stored blob is sealed under the row's REAL key_id, so it
        // round-trips through Kek::open - the exact property the non-atomic path
        // could silently violate on a crash between insert and reseal.
        let kek = test_kek();
        let db = Db::open_in_memory().unwrap();
        let secret = b"private-key-bytes";
        let key_id = db
            .insert_key_sealed("g1", b"spki-der", |key_id| kek.seal("g1", key_id, secret))
            .unwrap();
        let active = db.active_key("g1").unwrap().expect("active key present");
        assert_eq!(active.key_id, key_id);
        let opened = kek.open("g1", active.key_id, &active.sealed_pkcs8).unwrap();
        assert_eq!(opened, secret);
    }

    #[test]
    fn rotate_key_sealed_retires_old_and_binds_new_blob() {
        let kek = test_kek();
        let db = Db::open_in_memory().unwrap();
        db.insert_key_sealed("g1", b"spki-1", |id| kek.seal("g1", id, b"secret-1"))
            .unwrap();
        let new_id = db
            .rotate_key_sealed("g1", b"spki-2", |id| kek.seal("g1", id, b"secret-2"))
            .unwrap();
        let active = db.active_key("g1").unwrap().expect("active key present");
        assert_eq!(active.key_id, new_id, "the rotated-in key is active");
        assert_eq!(active.spki_der, b"spki-2");
        // The new active blob opens under its own id.
        let opened = kek.open("g1", active.key_id, &active.sealed_pkcs8).unwrap();
        assert_eq!(opened, b"secret-2");
    }

    #[test]
    fn service_key_insert_is_write_once() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.get_service_key("master-seed-v1").unwrap().is_none());
        assert!(db
            .insert_service_key("master-seed-v1", b"sealed-1")
            .unwrap());
        // A second insert for the same purpose must be refused, leaving the
        // original blob untouched (never silently overwrite key material).
        assert!(!db
            .insert_service_key("master-seed-v1", b"sealed-2")
            .unwrap());
        assert_eq!(
            db.get_service_key("master-seed-v1").unwrap().unwrap(),
            b"sealed-1"
        );
    }

    #[test]
    fn dedup_register_already_yours_and_taken() {
        let db = Db::open_in_memory().unwrap();
        let value = [0xabu8; 64];
        let r1 = db
            .register_dedup(&[1u8; 16], &value, "owner-a", "email-domain")
            .unwrap();
        let ref1 = match r1 {
            DedupRegister::Registered { entry_ref } => entry_ref,
            _ => panic!("first register must be Registered"),
        };
        // Same value, same owner: already_yours with the SAME entry ref (the
        // fresh candidate ref [2;16] must be discarded).
        match db
            .register_dedup(&[2u8; 16], &value, "owner-a", "email-domain")
            .unwrap()
        {
            DedupRegister::AlreadyYours { entry_ref } => assert_eq!(entry_ref, ref1),
            _ => panic!("same owner re-register must be AlreadyYours"),
        }
        // Same value, different owner: taken.
        assert!(matches!(
            db.register_dedup(&[3u8; 16], &value, "owner-b", "email-domain")
                .unwrap(),
            DedupRegister::Taken
        ));
    }

    #[test]
    fn dedup_register_race_has_exactly_one_winner() {
        use std::sync::Arc;
        let db = Arc::new(Db::open_in_memory().unwrap());
        let value = Arc::new([0x11u8; 64]);
        let mut handles = Vec::new();
        for i in 0..16u8 {
            let db = db.clone();
            let value = value.clone();
            handles.push(std::thread::spawn(move || {
                let mut entry_ref = [0u8; 16];
                entry_ref[0] = i;
                let owner = format!("owner-{i}");
                db.register_dedup(&entry_ref, value.as_ref(), &owner, "oauth-account")
                    .unwrap()
            }));
        }
        let mut registered = 0;
        let mut taken = 0;
        for h in handles {
            match h.join().unwrap() {
                DedupRegister::Registered { .. } => registered += 1,
                DedupRegister::Taken => taken += 1,
                DedupRegister::AlreadyYours { .. } => panic!("distinct owners cannot own it"),
            }
        }
        assert_eq!(registered, 1, "exactly one concurrent register may win");
        assert_eq!(taken, 15, "all losers must see Taken");
    }

    #[test]
    fn dedup_release_owner_checked_and_idempotent() {
        let db = Db::open_in_memory().unwrap();
        db.register_dedup(&[1u8; 16], &[0x22u8; 64], "owner-a", "email-domain")
            .unwrap();
        // Wrong owner: refused, row intact.
        assert!(matches!(
            db.release_dedup(&[1u8; 16], "owner-b").unwrap(),
            DedupRelease::OwnerMismatch
        ));
        assert!(db.dedup_entry_by_ref(&[1u8; 16]).unwrap().is_some());
        // Right owner: released.
        assert!(matches!(
            db.release_dedup(&[1u8; 16], "owner-a").unwrap(),
            DedupRelease::Released
        ));
        assert!(db.dedup_entry_by_ref(&[1u8; 16]).unwrap().is_none());
        // Releasing again: NotFound (idempotent retry surface).
        assert!(matches!(
            db.release_dedup(&[1u8; 16], "owner-a").unwrap(),
            DedupRelease::NotFound
        ));
        // The value is registrable again after release.
        assert!(matches!(
            db.register_dedup(&[9u8; 16], &[0x22u8; 64], "owner-b", "email-domain")
                .unwrap(),
            DedupRegister::Registered { .. }
        ));
    }

    #[test]
    fn dedup_reassign_is_per_ref_owner_checked_and_atomic() {
        let db = Db::open_in_memory().unwrap();
        db.register_dedup(&[1u8; 16], &[1u8; 64], "donor", "email-domain")
            .unwrap();
        db.register_dedup(&[2u8; 16], &[2u8; 64], "donor", "oauth-account")
            .unwrap();
        db.register_dedup(&[3u8; 16], &[3u8; 64], "bystander", "email-domain")
            .unwrap();

        // A batch containing a ref owned by a third party must change NOTHING.
        let refs: Vec<Vec<u8>> = vec![vec![1u8; 16], vec![3u8; 16]];
        assert!(matches!(
            db.reassign_dedup(&refs, "donor", "survivor").unwrap(),
            DedupReassign::OwnerMismatch
        ));
        assert_eq!(
            db.dedup_entry_by_ref(&[1u8; 16])
                .unwrap()
                .unwrap()
                .owner_tag,
            "donor",
            "atomicity: the valid ref in a failed batch must not move"
        );

        // A batch with an unknown ref must also change nothing.
        let refs: Vec<Vec<u8>> = vec![vec![1u8; 16], vec![0xffu8; 16]];
        assert!(matches!(
            db.reassign_dedup(&refs, "donor", "survivor").unwrap(),
            DedupReassign::NotFound
        ));

        // The explicit donor refs move; the bystander's entry is untouched.
        let refs: Vec<Vec<u8>> = vec![vec![1u8; 16], vec![2u8; 16]];
        match db.reassign_dedup(&refs, "donor", "survivor").unwrap() {
            DedupReassign::Reassigned { moved } => assert_eq!(moved, 2),
            _ => panic!("reassign must succeed"),
        }
        assert_eq!(
            db.dedup_entry_by_ref(&[1u8; 16])
                .unwrap()
                .unwrap()
                .owner_tag,
            "survivor"
        );
        assert_eq!(
            db.dedup_entry_by_ref(&[3u8; 16])
                .unwrap()
                .unwrap()
                .owner_tag,
            "bystander"
        );

        // Retry after full success: idempotent (0 moved, still Reassigned).
        match db.reassign_dedup(&refs, "donor", "survivor").unwrap() {
            DedupReassign::Reassigned { moved } => assert_eq!(moved, 0),
            _ => panic!("idempotent retry must succeed"),
        }

        // Reverse merge: exactly the recorded refs move back.
        match db.reassign_dedup(&refs, "survivor", "donor").unwrap() {
            DedupReassign::Reassigned { moved } => assert_eq!(moved, 2),
            _ => panic!("reverse reassign must succeed"),
        }
        assert_eq!(
            db.dedup_entry_by_ref(&[2u8; 16])
                .unwrap()
                .unwrap()
                .owner_tag,
            "donor"
        );
    }

    #[test]
    fn rotate_key_sealed_rolls_back_when_reseal_fails() {
        // A failed reseal during rotation must roll back BOTH the retire and the
        // insert, leaving the original active key intact and openable.
        let kek = test_kek();
        let db = Db::open_in_memory().unwrap();
        db.insert_key_sealed("g1", b"spki-1", |id| kek.seal("g1", id, b"secret-1"))
            .unwrap();
        let before = db.active_key("g1").unwrap().expect("active key present");

        let r = db.rotate_key_sealed("g1", b"spki-2", |_id| Err("seal boom".to_string()));
        assert!(r.is_err());

        let after = db
            .active_key("g1")
            .unwrap()
            .expect("original key still active");
        assert_eq!(after.key_id, before.key_id, "the original key stays active");
        let opened = kek.open("g1", after.key_id, &after.sealed_pkcs8).unwrap();
        assert_eq!(opened, b"secret-1");
    }
}
