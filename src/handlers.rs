//! HTTP handlers.
//!
//! Endpoints (all reachable only over mTLS, with the peer identity pinned):
//!   POST /sign            { group_id, participant_id, version_id, blinded_message } -> { blind_signature }
//!   GET  /key?group_id=…  -> { status: "ready", public_key, key_id } | 202 { status: "pending" }
//!   POST /key?group_id=…  -> enqueue keygen; 202 { status: "pending" } (or 200 ready if it already exists)
//!   POST /key/rotate?group_id=…  -> ADMIN ONLY: rotate to a fresh key
//!   GET  /healthz         -> liveness
//!
//! ANONYMITY: `/sign` treats `blinded_message` as opaque bytes, signs it, and
//! returns the blind signature. It never logs the blinded message or the
//! signature. The audit log records only (group_id, participant_id, version_id).
//!
//! ASYNC KEYGEN (audit H1): safe-prime keygen is multi-second, so key creation
//! never blocks a request thread. `POST /key` and the auto-create path of
//! `GET /key` enqueue generation on a bounded worker pool (deduped per group)
//! and return immediately; `/sign` for a not-yet-ready key waits a short,
//! bounded time and otherwise returns `pending`.
//!
//! IDENTITY (audit M1/M3): every request carries a pinned [`ClientIdentity`]
//! (see `identity.rs`). `/key/rotate` requires the `Admin` role; the `/key*`
//! endpoints are rate-limited per identity and globally.

use crate::db::{self, Reservation};
use crate::error::{AppError, AppResult};
use crate::identity::ClientIdentity;
use crate::keygen::KeygenStatus;
use crate::ratelimit::{Decision, KeyDecision};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Maximum accepted base64 length for a blinded message: a 4096-bit modulus is
/// 512 bytes; base64 of 512 bytes is ~684 chars. Cap generously but finitely to
/// bound request size and reject obvious garbage early.
const MAX_BLINDED_B64: usize = 1024;
/// Bound identifier lengths to keep DB keys and logs sane.
const MAX_ID_LEN: usize = 256;
/// How long `/sign` will wait for a not-yet-ready key before returning pending.
/// Short enough not to pin a request for seconds; long enough to absorb a key
/// that is nearly done.
const SIGN_KEY_WAIT: Duration = Duration::from_millis(750);

#[derive(Deserialize)]
pub struct SignRequest {
    pub group_id: String,
    pub participant_id: String,
    pub version_id: String,
    /// base64 (standard) of the blinded message bytes.
    pub blinded_message: String,
}

#[derive(Serialize)]
pub struct SignResponse {
    /// base64 (standard) of the blind signature bytes.
    pub blind_signature: String,
}

#[derive(Deserialize)]
pub struct GroupQuery {
    pub group_id: String,
}

/// Response for the `/key` endpoints. `status` is always present; the public
/// key fields are present only when the key is ready.
#[derive(Serialize)]
pub struct KeyResponse {
    pub group_id: String,
    /// "ready" or "pending".
    pub status: &'static str,
    /// base64 (standard) SPKI DER public key (present iff ready).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<i64>,
}

impl KeyResponse {
    fn ready(group_id: String, spki_der: &[u8], key_id: i64) -> Self {
        Self {
            group_id,
            status: "ready",
            public_key: Some(B64.encode(spki_der)),
            key_id: Some(key_id),
        }
    }

    fn pending(group_id: String) -> Self {
        Self {
            group_id,
            status: "pending",
            public_key: None,
            key_id: None,
        }
    }
}

fn validate_id(value: &str, field: &'static str) -> AppResult<()> {
    if value.is_empty() {
        return Err(AppError::BadRequest(match field {
            "group_id" => "group_id is empty",
            "participant_id" => "participant_id is empty",
            "version_id" => "version_id is empty",
            _ => "id is empty",
        }));
    }
    if value.len() > MAX_ID_LEN {
        return Err(AppError::BadRequest("identifier too long"));
    }
    Ok(())
}

/// Apply the `/key*` rate limit for the calling identity, mapping a denial to
/// the rate-limited error.
fn check_key_rate_limit(state: &AppState, identity: &ClientIdentity) -> AppResult<()> {
    match state.key_rate_limiter.check(&identity.name) {
        KeyDecision::Allow => Ok(()),
        KeyDecision::DenyIdentity | KeyDecision::DenyGlobal => Err(AppError::RateLimited),
    }
}

pub async fn healthz() -> &'static str {
    "ok"
}

/// POST /sign — blind-sign a blinded message, enforcing one-per-tuple + rate
/// limits. If the group key is not yet generated, waits a short bounded time;
/// if it is still not ready, returns 202 pending instead of blocking a thread.
pub async fn sign(
    State(state): State<Arc<AppState>>,
    _identity: ClientIdentity,
    Json(req): Json<SignRequest>,
) -> AppResult<Json<SignResponse>> {
    validate_id(&req.group_id, "group_id")?;
    validate_id(&req.participant_id, "participant_id")?;
    validate_id(&req.version_id, "version_id")?;

    if req.blinded_message.is_empty() || req.blinded_message.len() > MAX_BLINDED_B64 {
        return Err(AppError::BadRequest("blinded_message length out of range"));
    }
    let blinded = B64
        .decode(req.blinded_message.as_bytes())
        .map_err(|_| AppError::BadRequest("blinded_message is not valid base64"))?;

    // Ensure the group key is ready before doing the (blocking) signing work.
    // This bounds the wait so a cold key never pins a request thread for the
    // full multi-second keygen.
    if state.auto_create_keys {
        match state
            .keygen
            .wait_ready(&req.group_id, SIGN_KEY_WAIT)
            .await
            .map_err(AppError::Internal)?
        {
            KeygenStatus::Ready => {}
            KeygenStatus::Pending => return Err(AppError::KeyPending),
            KeygenStatus::Failed(e) => return Err(AppError::Internal(e)),
        }
    } else if state
        .keygen
        .active_key(&req.group_id)
        .map_err(AppError::Internal)?
        .is_none()
    {
        return Err(AppError::NoSuchKey);
    }

    // All DB + crypto is synchronous/blocking; isolate it from the async runtime.
    let result = tokio::task::spawn_blocking(move || sign_blocking(state, req, blinded))
        .await
        .map_err(|e| AppError::Internal(format!("join error: {e}")))?;

    result.map(Json)
}

fn sign_blocking(
    state: Arc<AppState>,
    req: SignRequest,
    blinded: Vec<u8>,
) -> AppResult<SignResponse> {
    // 1. Rate-limit checks (participant + global) BEFORE reserving a slot.
    match state
        .rate_limiter
        .check(&state.db, &req.participant_id)
        .map_err(AppError::Internal)?
    {
        Decision::Allow => {}
        Decision::DenyParticipant | Decision::DenyGlobal => return Err(AppError::RateLimited),
    }

    // 2. Record-first reservation: insert the issuance row BEFORE signing. The
    //    UNIQUE(group_id, participant_id, version_id) index makes a concurrent
    //    double-issue lose the race here, closing the check-then-act gap.
    let reservation = state
        .db
        .reserve_issuance(&req.group_id, &req.participant_id, &req.version_id)
        .map_err(AppError::Internal)?;
    let issuance_id = match reservation {
        Reservation::Reserved(id) => id,
        Reservation::AlreadyIssued => return Err(AppError::AlreadyIssued),
    };

    // 3. Load (or lazily create) the group key, then blind-sign. The key should
    //    already be ready (the async wait above), but get_or_create_key is the
    //    final guard. If anything here fails we roll the reservation back so a
    //    transient error does not permanently consume the participant's token.
    let signed = (|| -> AppResult<Vec<u8>> {
        let (pkcs8, _spki) = db::get_or_create_key(
            &state.db,
            &state.kek,
            &req.group_id,
            state.key_bits,
            state.auto_create_keys,
        )
        .map_err(|e| {
            if e == "no key" {
                AppError::NoSuchKey
            } else {
                AppError::Internal(e)
            }
        })?;

        let sig = crate::crypto::blind_sign(&pkcs8, &req.version_id, &blinded)
            .map_err(|e| AppError::Internal(format!("blind_sign failed: {e}")))?;
        Ok(sig)
    })();

    let sig = match signed {
        Ok(s) => s,
        Err(e) => {
            // Roll back the reservation; ignore secondary delete errors but log.
            if let Err(del) = state.db.delete_issuance(issuance_id) {
                tracing::error!(error = %del, "failed to roll back issuance reservation");
            }
            return Err(e);
        }
    };

    // 4. Audit log: identity tuple only. NEVER the blinded message or signature.
    tracing::info!(
        group_id = %req.group_id,
        participant_id = %req.participant_id,
        version_id = %req.version_id,
        "issued blind signature"
    );

    Ok(SignResponse {
        blind_signature: B64.encode(&sig),
    })
}

/// GET /key?group_id=… — report the active public key (ready) or that a key is
/// being generated (pending). With auto-create on, a missing key is enqueued
/// and reported pending; the caller polls. With auto-create off, a missing key
/// is 404.
pub async fn get_key(
    State(state): State<Arc<AppState>>,
    identity: ClientIdentity,
    Query(q): Query<GroupQuery>,
) -> AppResult<(StatusCode, Json<KeyResponse>)> {
    validate_id(&q.group_id, "group_id")?;
    check_key_rate_limit(&state, &identity)?;

    // Already ready?
    if let Some((key_id, spki)) = state
        .keygen
        .active_key(&q.group_id)
        .map_err(AppError::Internal)?
    {
        return Ok((
            StatusCode::OK,
            Json(KeyResponse::ready(q.group_id, &spki, key_id)),
        ));
    }
    if !state.auto_create_keys {
        return Err(AppError::NoSuchKey);
    }
    // Enqueue (deduped) and report pending. Does NOT wait for generation.
    match state
        .keygen
        .ensure(&q.group_id)
        .map_err(AppError::Internal)?
    {
        KeygenStatus::Ready => {
            // Raced to ready between the check above and ensure().
            let (key_id, spki) = state
                .keygen
                .active_key(&q.group_id)
                .map_err(AppError::Internal)?
                .ok_or_else(|| AppError::Internal("key vanished after ready".into()))?;
            Ok((
                StatusCode::OK,
                Json(KeyResponse::ready(q.group_id, &spki, key_id)),
            ))
        }
        KeygenStatus::Pending => Ok((StatusCode::ACCEPTED, Json(KeyResponse::pending(q.group_id)))),
        KeygenStatus::Failed(e) => Err(AppError::Internal(e)),
    }
}

/// POST /key?group_id=… — enqueue key creation if absent and return pending
/// immediately (idempotent: returns the existing key as ready if one is active).
pub async fn create_key(
    State(state): State<Arc<AppState>>,
    identity: ClientIdentity,
    Query(q): Query<GroupQuery>,
) -> AppResult<(StatusCode, Json<KeyResponse>)> {
    validate_id(&q.group_id, "group_id")?;
    check_key_rate_limit(&state, &identity)?;

    match state
        .keygen
        .ensure(&q.group_id)
        .map_err(AppError::Internal)?
    {
        KeygenStatus::Ready => {
            let (key_id, spki) = state
                .keygen
                .active_key(&q.group_id)
                .map_err(AppError::Internal)?
                .ok_or_else(|| AppError::Internal("key vanished after ready".into()))?;
            Ok((
                StatusCode::OK,
                Json(KeyResponse::ready(q.group_id, &spki, key_id)),
            ))
        }
        KeygenStatus::Pending => {
            tracing::info!(group_id = %q.group_id, "enqueued group key generation");
            Ok((StatusCode::ACCEPTED, Json(KeyResponse::pending(q.group_id))))
        }
        KeygenStatus::Failed(e) => Err(AppError::Internal(e)),
    }
}

/// POST /key/rotate?group_id=… — ADMIN ONLY. Retire the current key, generate a
/// fresh one. Rotation is a deliberate admin action, so it is synchronous (the
/// admin receives the new key), but bounded by the keygen concurrency cap.
///
/// Rotation invalidates outstanding tokens signed under the retired key.
pub async fn rotate_key(
    State(state): State<Arc<AppState>>,
    identity: ClientIdentity,
    Query(q): Query<GroupQuery>,
) -> AppResult<Json<KeyResponse>> {
    validate_id(&q.group_id, "group_id")?;
    if !identity.is_admin() {
        tracing::warn!(
            identity = %identity.name,
            group_id = %q.group_id,
            "rejected /key/rotate: caller is not an admin identity"
        );
        return Err(AppError::Forbidden(
            "key rotation requires an admin client identity",
        ));
    }
    check_key_rate_limit(&state, &identity)?;

    let spki = state
        .keygen
        .rotate(&q.group_id)
        .await
        .map_err(AppError::Internal)?;
    let (key_id, _) = state
        .keygen
        .active_key(&q.group_id)
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::Internal("key vanished after rotate".into()))?;
    tracing::info!(
        group_id = %q.group_id,
        key_id,
        admin = %identity.name,
        "rotated group key"
    );
    Ok(Json(KeyResponse::ready(q.group_id, &spki, key_id)))
}
