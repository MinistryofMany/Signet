//! HTTP handlers.
//!
//! Endpoints (all reachable only over mTLS):
//!   POST /sign            { group_id, participant_id, version_id, blinded_message } -> { blind_signature }
//!   GET  /key?group_id=…  -> { group_id, public_key, key_id }   (SPKI, base64)
//!   POST /key?group_id=…  -> create the group key if absent       (idempotent)
//!   POST /key/rotate?group_id=…  -> rotate to a fresh key
//!   GET  /healthz         -> liveness
//!
//! ANONYMITY: `/sign` treats `blinded_message` as opaque bytes, signs it, and
//! returns the blind signature. It never logs the blinded message or the
//! signature. The audit log records only (group_id, participant_id, version_id).

use crate::db::{self, Reservation};
use crate::error::{AppError, AppResult};
use crate::ratelimit::Decision;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Maximum accepted base64 length for a blinded message: a 4096-bit modulus is
/// 512 bytes; base64 of 512 bytes is ~684 chars. Cap generously but finitely to
/// bound request size and reject obvious garbage early.
const MAX_BLINDED_B64: usize = 1024;
/// Bound identifier lengths to keep DB keys and logs sane.
const MAX_ID_LEN: usize = 256;

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

#[derive(Serialize)]
pub struct KeyResponse {
    pub group_id: String,
    /// base64 (standard) SPKI DER public key.
    pub public_key: String,
    pub key_id: i64,
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

pub async fn healthz() -> &'static str {
    "ok"
}

/// POST /sign — blind-sign a blinded message, enforcing one-per-tuple + rate
/// limits. Runs the blocking crypto/DB work on a blocking thread.
pub async fn sign(
    State(state): State<Arc<AppState>>,
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

    // 3. Load (or lazily create) the group key, then blind-sign. If anything
    //    here fails we roll the reservation back so a transient error does not
    //    permanently consume the participant's single allowed token.
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

/// GET /key?group_id=… — return the active public key (SPKI, base64). Lazily
/// creates the key if auto-create is on; otherwise 404 when absent.
pub async fn get_key(
    State(state): State<Arc<AppState>>,
    Query(q): Query<GroupQuery>,
) -> AppResult<Json<KeyResponse>> {
    validate_id(&q.group_id, "group_id")?;
    let auto = state.auto_create_keys;
    let result = tokio::task::spawn_blocking(move || -> AppResult<KeyResponse> {
        if let Some(k) = state.db.active_key(&q.group_id).map_err(AppError::Internal)? {
            return Ok(KeyResponse {
                group_id: q.group_id,
                public_key: B64.encode(&k.spki_der),
                key_id: k.key_id,
            });
        }
        if !auto {
            return Err(AppError::NoSuchKey);
        }
        let (_pkcs8, spki) =
            db::create_key(&state.db, &state.kek, &q.group_id, state.key_bits)
                .map_err(AppError::Internal)?;
        let k = state
            .db
            .active_key(&q.group_id)
            .map_err(AppError::Internal)?
            .ok_or_else(|| AppError::Internal("key vanished after create".into()))?;
        Ok(KeyResponse {
            group_id: q.group_id,
            public_key: B64.encode(&spki),
            key_id: k.key_id,
        })
    })
    .await
    .map_err(|e| AppError::Internal(format!("join error: {e}")))?;
    result.map(Json)
}

/// POST /key?group_id=… — explicitly create the key if absent (idempotent:
/// returns the existing key if one is already active).
pub async fn create_key(
    State(state): State<Arc<AppState>>,
    Query(q): Query<GroupQuery>,
) -> AppResult<Json<KeyResponse>> {
    validate_id(&q.group_id, "group_id")?;
    let result = tokio::task::spawn_blocking(move || -> AppResult<KeyResponse> {
        if let Some(k) = state.db.active_key(&q.group_id).map_err(AppError::Internal)? {
            return Ok(KeyResponse {
                group_id: q.group_id,
                public_key: B64.encode(&k.spki_der),
                key_id: k.key_id,
            });
        }
        let (_pkcs8, spki) =
            db::create_key(&state.db, &state.kek, &q.group_id, state.key_bits)
                .map_err(AppError::Internal)?;
        let k = state
            .db
            .active_key(&q.group_id)
            .map_err(AppError::Internal)?
            .ok_or_else(|| AppError::Internal("key vanished after create".into()))?;
        tracing::info!(group_id = %q.group_id, key_id = k.key_id, "created group key");
        Ok(KeyResponse {
            group_id: q.group_id,
            public_key: B64.encode(&spki),
            key_id: k.key_id,
        })
    })
    .await
    .map_err(|e| AppError::Internal(format!("join error: {e}")))?;
    result.map(Json)
}

/// POST /key/rotate?group_id=… — retire the current key, generate a fresh one.
pub async fn rotate_key(
    State(state): State<Arc<AppState>>,
    Query(q): Query<GroupQuery>,
) -> AppResult<Json<KeyResponse>> {
    validate_id(&q.group_id, "group_id")?;
    let result = tokio::task::spawn_blocking(move || -> AppResult<KeyResponse> {
        let spki = db::rotate_key(&state.db, &state.kek, &q.group_id, state.key_bits)
            .map_err(AppError::Internal)?;
        let k = state
            .db
            .active_key(&q.group_id)
            .map_err(AppError::Internal)?
            .ok_or_else(|| AppError::Internal("key vanished after rotate".into()))?;
        tracing::info!(group_id = %q.group_id, key_id = k.key_id, "rotated group key");
        Ok(KeyResponse {
            group_id: q.group_id,
            public_key: B64.encode(&spki),
            key_id: k.key_id,
        })
    })
    .await
    .map_err(|e| AppError::Internal(format!("join error: {e}")))?;
    result.map(Json)
}
