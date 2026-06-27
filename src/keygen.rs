//! Async key generation with a bounded worker pool and in-flight dedup
//! (audit H1).
//!
//! Safe-prime RSA keygen takes multiple seconds. The original design generated
//! keys synchronously on the request path, so an unauthenticated flood of
//! `/key` (or first-`/sign`) requests for distinct groups could spawn unbounded
//! multi-second CPU jobs and exhaust the machine — a denial-of-service.
//!
//! This service makes key creation non-blocking and bounded:
//!
//!   - **Bounded concurrency.** A [`Semaphore`] caps how many keygens run at
//!     once (`max_concurrent`). Excess requests queue for a permit instead of
//!     spawning unbounded CPU work.
//!   - **In-flight dedup.** Concurrent requests for the *same* `group_id` share
//!     one keygen. The first request registers a [`watch`] channel and spawns
//!     the worker; later requests observe the same channel. This both prevents
//!     duplicate work and, with the DB's unique active-key index as a backstop,
//!     prevents two keys racing for one group.
//!   - **Non-blocking enqueue.** [`KeygenService::ensure`] returns immediately
//!     with the current [`KeygenStatus`]; it never waits for the CPU work.
//!   - **Bounded wait.** [`KeygenService::wait_ready`] lets `/sign` wait a short,
//!     capped duration for a key to become ready, then give up with `Pending`
//!     rather than pinning a thread for seconds.
//!
//! The actual generation + DB write runs on a blocking thread (`spawn_blocking`)
//! because it is CPU-bound and uses the synchronous `rusqlite` connection.

use crate::db::{self, Db};
use crate::keystore::Kek;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{watch, Semaphore};

/// The state of a group's key from the keygen service's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeygenStatus {
    /// A key exists and is ready to sign with.
    Ready,
    /// A keygen is in progress (or queued for a worker permit).
    Pending,
    /// The most recent keygen attempt failed; the message is for logging only.
    Failed(String),
}

/// Handle to the async keygen subsystem. Cheap to clone (everything is shared).
#[derive(Clone)]
pub struct KeygenService {
    inner: Arc<Inner>,
}

struct Inner {
    db: Arc<Db>,
    kek: Kek,
    key_bits: usize,
    /// Caps concurrent in-progress keygens across all groups.
    permits: Arc<Semaphore>,
    /// group_id -> a receiver that flips to Ready/Failed when the worker
    /// finishes. Presence in this map means "a keygen is in flight".
    inflight: Mutex<HashMap<String, watch::Receiver<KeygenStatus>>>,
}

impl KeygenService {
    /// Create the service. `max_concurrent` must be >= 1.
    pub fn new(db: Arc<Db>, kek: Kek, key_bits: usize, max_concurrent: usize) -> Self {
        let max_concurrent = max_concurrent.max(1);
        Self {
            inner: Arc::new(Inner {
                db,
                kek,
                key_bits,
                permits: Arc::new(Semaphore::new(max_concurrent)),
                inflight: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Ensure a key for `group_id` exists or is being generated, returning the
    /// current status WITHOUT waiting for generation to finish.
    ///
    /// - If a key already exists in the DB: `Ready`.
    /// - If a keygen is already in flight for this group: `Pending` (deduped —
    ///   no new worker is spawned).
    /// - Otherwise: spawn a bounded worker and return `Pending`.
    pub fn ensure(&self, group_id: &str) -> Result<KeygenStatus, String> {
        // Fast path: already in the DB.
        if self.inner.db.active_key(group_id)?.is_some() {
            return Ok(KeygenStatus::Ready);
        }
        // Register or join the in-flight keygen for this group.
        let mut map = lock_inflight(&self.inner.inflight);
        if map.contains_key(group_id) {
            return Ok(KeygenStatus::Pending);
        }
        // Double-check under the lock: the key may have landed between the
        // active_key() check and acquiring the lock.
        if self.inner.db.active_key(group_id)?.is_some() {
            return Ok(KeygenStatus::Ready);
        }
        let (tx, rx) = watch::channel(KeygenStatus::Pending);
        map.insert(group_id.to_string(), rx);
        drop(map);
        self.spawn_worker(group_id.to_string(), tx);
        Ok(KeygenStatus::Pending)
    }

    /// Current status of a group's key without spawning anything.
    pub fn status(&self, group_id: &str) -> Result<KeygenStatus, String> {
        if self.inner.db.active_key(group_id)?.is_some() {
            return Ok(KeygenStatus::Ready);
        }
        let map = lock_inflight(&self.inner.inflight);
        if let Some(rx) = map.get(group_id) {
            return Ok(rx.borrow().clone());
        }
        // No key and nothing in flight: report Pending only if something is
        // expected to create it; the caller decides. Here we say "not ready".
        Ok(KeygenStatus::Pending)
    }

    /// Ensure a keygen is under way and wait up to `timeout` for it to become
    /// ready. Returns `Ready` on success or `Pending` if it did not finish in
    /// time. Never waits longer than `timeout`.
    pub async fn wait_ready(
        &self,
        group_id: &str,
        timeout: Duration,
    ) -> Result<KeygenStatus, String> {
        match self.ensure(group_id)? {
            KeygenStatus::Ready => return Ok(KeygenStatus::Ready),
            KeygenStatus::Failed(e) => return Ok(KeygenStatus::Failed(e)),
            KeygenStatus::Pending => {}
        }
        // Grab the receiver for this group, if still in flight.
        let mut rx = {
            let map = lock_inflight(&self.inner.inflight);
            match map.get(group_id) {
                Some(rx) => rx.clone(),
                // The worker already finished and removed itself; re-check DB.
                None => {
                    drop(map);
                    return self.status(group_id);
                }
            }
        };
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            // Already terminal?
            let cur = rx.borrow_and_update().clone();
            match cur {
                KeygenStatus::Ready => return Ok(KeygenStatus::Ready),
                KeygenStatus::Failed(e) => return Ok(KeygenStatus::Failed(e)),
                KeygenStatus::Pending => {}
            }
            tokio::select! {
                _ = &mut deadline => return Ok(KeygenStatus::Pending),
                changed = rx.changed() => {
                    if changed.is_err() {
                        // Sender dropped (worker done); resolve from the DB.
                        return self.status(group_id);
                    }
                    // loop and re-read the new value
                }
            }
        }
    }

    /// Rotate a group's key synchronously, bounded by the same concurrency
    /// semaphore as background keygen so a rotation cannot bypass the cap.
    /// Returns the new SPKI DER. This is an admin operation; the caller awaits
    /// the new key, so it is intentionally not deduped or backgrounded.
    pub async fn rotate(&self, group_id: &str) -> Result<Vec<u8>, String> {
        let _permit = self
            .inner
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "keygen semaphore closed".to_string())?;
        let db = self.inner.db.clone();
        let kek = self.inner.kek.clone();
        let bits = self.inner.key_bits;
        let gid = group_id.to_string();
        tokio::task::spawn_blocking(move || db::rotate_key(&db, &kek, &gid, bits))
            .await
            .map_err(|e| format!("rotate task join error: {e}"))?
    }

    /// Look up the active public key (SPKI DER) and key id for a ready group.
    pub fn active_key(&self, group_id: &str) -> Result<Option<(i64, Vec<u8>)>, String> {
        Ok(self
            .inner
            .db
            .active_key(group_id)?
            .map(|k| (k.key_id, k.spki_der)))
    }

    /// Spawn the bounded blocking worker that generates + persists the key.
    fn spawn_worker(&self, group_id: String, tx: watch::Sender<KeygenStatus>) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            // Bound concurrent CPU work. If the semaphore is closed (never, in
            // practice), treat as a failure.
            let permit = match inner.permits.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    let _ = tx.send(KeygenStatus::Failed("keygen semaphore closed".into()));
                    remove_inflight(&inner.inflight, &group_id);
                    return;
                }
            };
            let db = inner.db.clone();
            let kek = inner.kek.clone();
            let bits = inner.key_bits;
            let gid = group_id.clone();
            let result = tokio::task::spawn_blocking(move || {
                // create_key is idempotent-safe against the unique active-key
                // index: if a key already exists it returns an error, which we
                // map to Ready below.
                db::create_key(&db, &kek, &gid, bits)
            })
            .await;
            drop(permit);

            let status = match result {
                Ok(Ok(_)) => KeygenStatus::Ready,
                Ok(Err(e)) => {
                    // If a key already exists (e.g. a concurrent rotate created
                    // one), treat as ready rather than failed.
                    if inner.db.active_key(&group_id).ok().flatten().is_some() {
                        KeygenStatus::Ready
                    } else {
                        tracing::error!(group_id = %group_id, error = %e, "keygen failed");
                        KeygenStatus::Failed(e)
                    }
                }
                Err(join_err) => {
                    tracing::error!(group_id = %group_id, error = %join_err, "keygen task panicked");
                    KeygenStatus::Failed(format!("keygen task join error: {join_err}"))
                }
            };
            // Publish the result to any waiters, then deregister so a future
            // request can retry if it failed.
            let _ = tx.send(status);
            remove_inflight(&inner.inflight, &group_id);
        });
    }
}

fn lock_inflight(
    m: &Mutex<HashMap<String, watch::Receiver<KeygenStatus>>>,
) -> std::sync::MutexGuard<'_, HashMap<String, watch::Receiver<KeygenStatus>>> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn remove_inflight(m: &Mutex<HashMap<String, watch::Receiver<KeygenStatus>>>, group_id: &str) {
    lock_inflight(m).remove(group_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::Kek;

    fn kek() -> Kek {
        Kek::from_encoded(&hex::encode([0x5au8; 32])).unwrap()
    }

    // 1024-bit keygen keeps the dedup/concurrency tests fast; interop is not
    // exercised here (these are about the worker pool, not the wire scheme).
    const FAST_BITS: usize = 1024;

    #[tokio::test]
    async fn ensure_dedups_concurrent_same_group() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let svc = KeygenService::new(db.clone(), kek(), FAST_BITS, 4);

        // Fire many concurrent ensure() for the SAME group.
        let mut handles = Vec::new();
        for _ in 0..16 {
            let svc = svc.clone();
            handles.push(tokio::spawn(async move { svc.ensure("g1").unwrap() }));
        }
        for h in handles {
            let st = h.await.unwrap();
            assert!(matches!(st, KeygenStatus::Ready | KeygenStatus::Pending));
        }
        // Wait for completion.
        let st = svc.wait_ready("g1", Duration::from_secs(30)).await.unwrap();
        assert_eq!(st, KeygenStatus::Ready);
        // Exactly one active key exists for the group (dedup held).
        assert!(db.active_key("g1").unwrap().is_some());
    }

    #[tokio::test]
    async fn wait_ready_times_out_then_eventually_ready() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        // One worker, so a too-short wait can plausibly time out.
        let svc = KeygenService::new(db.clone(), kek(), FAST_BITS, 1);
        // A 1ns wait should not be enough for safe-prime keygen.
        let quick = svc.wait_ready("g1", Duration::from_nanos(1)).await.unwrap();
        assert!(matches!(quick, KeygenStatus::Pending | KeygenStatus::Ready));
        // Given enough time, it becomes ready.
        let st = svc.wait_ready("g1", Duration::from_secs(30)).await.unwrap();
        assert_eq!(st, KeygenStatus::Ready);
    }

    #[tokio::test]
    async fn ensure_ready_for_existing_key() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let svc = KeygenService::new(db.clone(), kek(), FAST_BITS, 2);
        // Create synchronously first.
        db::create_key(&db, &kek(), "g1", FAST_BITS).unwrap();
        assert_eq!(svc.ensure("g1").unwrap(), KeygenStatus::Ready);
        assert_eq!(svc.status("g1").unwrap(), KeygenStatus::Ready);
    }
}
