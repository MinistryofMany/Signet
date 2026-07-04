//! HTTP handlers.
//!
//! Endpoints (all reachable only over mTLS, with the peer identity pinned):
//!   POST /sign            { group_id, participant_id, version_id, blinded_message } -> { blind_signature }
//!   GET  /key?group_id=…  -> { status: "ready", public_key, key_id } | 202 { status: "pending" }
//!   POST /key?group_id=…  -> enqueue keygen; 202 { status: "pending" } (or 200 ready if it already exists)
//!   POST /key/rotate?group_id=…  -> ADMIN ONLY: rotate to a fresh key
//!   GET  /healthz         -> liveness
//!
//! PRF surface (mounted ONLY when the fail-closed boot policy enabled it;
//! every route additionally requires the caller on SIGNET_PRF_CLIENT_IDS):
//!   POST /prf/pairwise    { input } -> { output }            keyed HMAC oracle
//!   POST /prf/evaluate    { blinded_element } -> { evaluation_element, proof }
//!   GET  /prf/public-key  -> { suite, public_key }           the pinned pkS
//!   POST /prf/disclose    { entry_ref, owner_handle, client_id } -> { nullifier }
//!   POST /dedup/register  { value, owner_handle, badge_type } -> { status, entry_ref }
//!   POST /dedup/release   { entry_ref, owner_handle } -> { status }
//!   POST /dedup/reassign  { entry_refs, from_owner_handle, to_owner_handle } -> { status, reassigned }
//!
//! ANONYMITY: `/sign` treats `blinded_message` as opaque bytes, signs it, and
//! returns the blind signature. It never logs the blinded message or the
//! signature. The audit log records only (group_id, participant_id, version_id).
//! The PRF surface goes further: its logs record ONLY the pinned identity and
//! the endpoint — never inputs, outputs, values, handles, refs, or per-request
//! outcome status (an outcome like a dedup collision is visible only to the
//! caller; logging it would make credential-collision events readable and
//! timestamp-correlatable from the log stream). Authorization refusals emit a
//! payload-free warning.
//!
//! ASYNC KEYGEN (audit H1): safe-prime keygen is multi-second, so key creation
//! never blocks a request thread. `POST /key` and the auto-create path of
//! `GET /key` enqueue generation on a bounded worker pool (deduped per group)
//! and return immediately; `/sign` for a not-yet-ready key waits a short,
//! bounded time and otherwise returns `pending`.
//!
//! IDENTITY (audit M1/M3): every request carries a pinned [`ClientIdentity`]
//! (see `identity.rs`). `/key/rotate` requires the `Admin` role; the `/key*`
//! endpoints are rate-limited per identity and globally. The PRF/dedup routes
//! are gated per-route on `may_prf()` (the dedicated allow-list — mirroring
//! the `is_admin()` gate, never the open client-list convention) with their
//! own rate-limit bucket; conversely the blind-RSA surface refuses PRF-only
//! identities via `may_sign()`, so admitting Minister for PRF never widens
//! /sign.

use crate::db::{self, DedupReassign, DedupRegister, DedupRelease, Reservation};
use crate::error::{AppError, AppResult};
use crate::identity::ClientIdentity;
use crate::keygen::KeygenStatus;
use crate::prf::{self, PrfError};
use crate::ratelimit::{Decision, KeyDecision};
use crate::state::{AppState, PrfState};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
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

/// Refuse PRF-only identities on the blind-RSA surface. Identities admitted
/// via the client/admin lists (or the open back-compat list) are unaffected —
/// a PRF-only identity could not even connect before the PRF list existed, so
/// this is a pure fail-closed narrowing, not a behavior change for deployed
/// clients.
fn require_sign_surface(identity: &ClientIdentity) -> AppResult<()> {
    if !identity.may_sign() {
        tracing::warn!(
            identity = %identity.name,
            "rejected blind-RSA surface request: PRF-only identity"
        );
        return Err(AppError::Forbidden(
            "this identity is authorized only for the PRF surface",
        ));
    }
    Ok(())
}

pub async fn healthz() -> &'static str {
    "ok"
}

/// POST /sign — blind-sign a blinded message, enforcing one-per-tuple + rate
/// limits. If the group key is not yet generated, waits a short bounded time;
/// if it is still not ready, returns 202 pending instead of blocking a thread.
pub async fn sign(
    State(state): State<Arc<AppState>>,
    identity: ClientIdentity,
    Json(req): Json<SignRequest>,
) -> AppResult<Json<SignResponse>> {
    require_sign_surface(&identity)?;
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
    require_sign_surface(&identity)?;
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
    require_sign_surface(&identity)?;
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
    require_sign_surface(&identity)?;
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

// ---------------------------------------------------------------------------
// PRF surface: /prf/* + /dedup/*
// ---------------------------------------------------------------------------

/// Cap on the opaque `/prf/pairwise` input, in BYTES of the UTF-8 string.
const MAX_PAIRWISE_INPUT: usize = 512;
/// Cap on `client_id` (mirrors the Minister-side clientId cap).
const MAX_CLIENT_ID_LEN: usize = 256;
/// Cap on `badge_type` (mirrors the shared badge-type registry slugs).
const MAX_BADGE_TYPE_LEN: usize = 64;
/// Cap on owner handles (Minister mints 22-char base64url handles; capped
/// generously but finitely).
const MAX_OWNER_HANDLE_LEN: usize = 128;
/// Length of a dedup entry ref (raw bytes).
const ENTRY_REF_LEN: usize = 16;
/// Cap on the number of refs in one /dedup/reassign batch.
const MAX_REASSIGN_REFS: usize = 256;

/// Per-route, fail-closed PRF authorization + the PRF rate-limit bucket.
///
/// Mirrors the `is_admin()` gate on /key/rotate, in TWO layers that must
/// agree: (1) the `prf_allowed` flag, pinned per connection by `classify()`
/// against the dedicated `SIGNET_PRF_CLIENT_IDS` set — connection-level
/// client classification (including the open back-compat client list) never
/// grants it; and (2) an in-handler membership re-check of the PINNED
/// identity name against the same set held on [`PrfState`] (immutable after
/// boot), so a future `classify()` refactor bug cannot silently widen the
/// PRF surface. Deliberate side effect of layer 2: an identity whose pinned
/// name came from another list (e.g. an allow-listed CN carrying a stray
/// PRF-colliding SAN) is refused — the audited name must ITSELF be the
/// PRF-authorized name. Authorization is checked before the rate limit so an
/// unauthorized caller always sees 403 and cannot consume budget.
fn require_prf<'a>(state: &'a AppState, identity: &ClientIdentity) -> AppResult<&'a PrfState> {
    let prf = state.prf.as_ref().ok_or_else(|| {
        // The PRF routes are only mounted when the state exists; reaching this
        // means the router was wired without it — refuse, never fail open.
        tracing::error!("PRF handler reached without PRF state");
        AppError::Internal("PRF surface unavailable".into())
    })?;
    if !identity.may_prf() {
        tracing::warn!(
            identity = %identity.name,
            "rejected PRF request: identity not on SIGNET_PRF_CLIENT_IDS"
        );
        return Err(AppError::Forbidden(
            "client identity is not authorized for the PRF surface",
        ));
    }
    if !prf.allowed_client_ids.contains(&identity.name) {
        tracing::warn!(
            identity = %identity.name,
            "rejected PRF request: pinned identity name is not on SIGNET_PRF_CLIENT_IDS \
             (second-layer allow-list check)"
        );
        return Err(AppError::Forbidden(
            "client identity is not authorized for the PRF surface",
        ));
    }
    match prf.rate_limiter.check(&identity.name) {
        KeyDecision::Allow => Ok(prf),
        KeyDecision::DenyIdentity | KeyDecision::DenyGlobal => Err(AppError::RateLimited),
    }
}

/// Run blocking dedup-ledger DB work off the async runtime (the `/sign`
/// convention, see [`sign`]): the single write-serialized SQLite connection
/// is shared with the blind-RSA surface, so ledger queries and transactions
/// must not occupy tokio worker threads or add tail latency to `/sign`.
async fn run_db_blocking<T, F>(f: F) -> AppResult<T>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| AppError::Internal(format!("join error: {e}")))?
        .map_err(AppError::Internal)
}

/// Decode a base64url-no-pad field, strictly. Failure is always a 400.
fn b64url_decode(value: &str, err: &'static str) -> AppResult<Vec<u8>> {
    B64URL
        .decode(value.as_bytes())
        .map_err(|_| AppError::BadRequest(err))
}

/// Validate a text field: non-empty and within its byte cap.
fn validate_text(value: &str, max: usize, err: &'static str) -> AppResult<()> {
    if value.is_empty() || value.len() > max {
        return Err(AppError::BadRequest(err));
    }
    Ok(())
}

/// Decode + validate an entry ref (base64url of exactly 16 bytes).
fn decode_entry_ref(value: &str) -> AppResult<Vec<u8>> {
    // 16 bytes -> 22 base64url chars; reject anything longer before decoding.
    if value.is_empty() || value.len() > 24 {
        return Err(AppError::BadRequest("entry_ref length out of range"));
    }
    let raw = b64url_decode(value, "entry_ref is not valid base64url")?;
    if raw.len() != ENTRY_REF_LEN {
        return Err(AppError::BadRequest("entry_ref has the wrong length"));
    }
    Ok(raw)
}

#[derive(Deserialize)]
pub struct PairwiseRequest {
    /// Opaque input string; HMAC'd verbatim (exact UTF-8 bytes).
    pub input: String,
}

#[derive(Serialize)]
pub struct PairwiseResponse {
    /// base64url (no padding) of HMAC-SHA256(pairwise secret, input).
    pub output: String,
}

/// POST /prf/pairwise — the keyed pairwise HMAC oracle. An HMAC oracle BY
/// DESIGN (Minister composes the tagged inputs), which is exactly why the
/// per-route fail-closed gate above exists. NEVER logs input or output.
pub async fn prf_pairwise(
    State(state): State<Arc<AppState>>,
    identity: ClientIdentity,
    Json(req): Json<PairwiseRequest>,
) -> AppResult<Json<PairwiseResponse>> {
    let prf = require_prf(&state, &identity)?;
    if req.input.is_empty() || req.input.len() > MAX_PAIRWISE_INPUT {
        return Err(AppError::BadRequest("input length out of range"));
    }
    let output = prf
        .keys
        .pairwise(req.input.as_bytes())
        .ok_or(AppError::NotFound(
            "the pairwise secret has not been imported",
        ))?;
    tracing::info!(identity = %identity.name, endpoint = "prf/pairwise", "served");
    Ok(Json(PairwiseResponse { output }))
}

#[derive(Deserialize)]
pub struct EvaluateRequest {
    /// base64url (no padding) of a serialized ristretto255 blinded element.
    pub blinded_element: String,
}

#[derive(Serialize)]
pub struct EvaluateResponse {
    /// base64url (no padding) of the serialized evaluation element.
    pub evaluation_element: String,
    /// base64url (no padding) of the serialized DLEQ proof (c || s).
    pub proof: String,
}

/// POST /prf/evaluate — blind VOPRF evaluation with a DLEQ proof. The input
/// is BLINDED: Signet never sees the underlying anchor. NEVER logs the
/// element or the result.
pub async fn prf_evaluate(
    State(state): State<Arc<AppState>>,
    identity: ClientIdentity,
    Json(req): Json<EvaluateRequest>,
) -> AppResult<Json<EvaluateResponse>> {
    let prf = require_prf(&state, &identity)?;
    // 32 bytes -> 43 base64url chars; bound before decoding.
    if req.blinded_element.is_empty() || req.blinded_element.len() > 64 {
        return Err(AppError::BadRequest("blinded_element length out of range"));
    }
    let raw = b64url_decode(
        &req.blinded_element,
        "blinded_element is not valid base64url",
    )?;
    let out = prf.keys.evaluate(&raw).map_err(|e| match e {
        PrfError::BadElement => {
            AppError::BadRequest("blinded_element is not a valid group element")
        }
    })?;
    tracing::info!(identity = %identity.name, endpoint = "prf/evaluate", "served");
    Ok(Json(EvaluateResponse {
        evaluation_element: B64URL.encode(out.evaluation_element),
        proof: B64URL.encode(out.proof),
    }))
}

#[derive(Serialize)]
pub struct PublicKeyResponse {
    /// The VOPRF ciphersuite identifier.
    pub suite: &'static str,
    /// base64url (no padding) of the serialized public key pkS — the same
    /// encoding as SIGNET_DEDUP_PUBKEY_PIN and the init output.
    pub public_key: String,
}

/// GET /prf/public-key — the pinned VOPRF public key, for client-side DLEQ
/// verification against an independently pinned copy.
pub async fn prf_public_key(
    State(state): State<Arc<AppState>>,
    identity: ClientIdentity,
) -> AppResult<Json<PublicKeyResponse>> {
    let prf = require_prf(&state, &identity)?;
    tracing::info!(identity = %identity.name, endpoint = "prf/public-key", "served");
    Ok(Json(PublicKeyResponse {
        suite: prf::SUITE,
        public_key: prf.keys.public_key_b64(),
    }))
}

#[derive(Deserialize)]
pub struct DiscloseRequest {
    /// base64url (no padding) of the 16-byte entry ref.
    pub entry_ref: String,
    /// The caller-asserted owner handle; must equal the stored owner_tag.
    pub owner_handle: String,
    /// The relying party's clientId.
    pub client_id: String,
}

#[derive(Serialize)]
pub struct DiscloseResponse {
    /// The per-RP disclosed nullifier, "mnv1:" + base64url(HMAC output).
    pub nullifier: String,
}

/// POST /prf/disclose — derive the per-RP nullifier from a STORED ledger
/// entry. Owner-checked: a mis-bound or swapped ref (a Minister-DB-write
/// attacker moving Badge.nullifierRef between users) fails closed with 403
/// rather than presenting another user's Sybil nullifier.
pub async fn prf_disclose(
    State(state): State<Arc<AppState>>,
    identity: ClientIdentity,
    Json(req): Json<DiscloseRequest>,
) -> AppResult<Json<DiscloseResponse>> {
    let prf = require_prf(&state, &identity)?;
    let entry_ref = decode_entry_ref(&req.entry_ref)?;
    validate_text(
        &req.owner_handle,
        MAX_OWNER_HANDLE_LEN,
        "owner_handle length out of range",
    )?;
    validate_text(
        &req.client_id,
        MAX_CLIENT_ID_LEN,
        "client_id length out of range",
    )?;
    let db = state.db.clone();
    let entry = run_db_blocking(move || db.dedup_entry_by_ref(&entry_ref))
        .await?
        .ok_or(AppError::NotFound("no such dedup entry"))?;
    if !db::owner_eq(&entry.owner_tag, &req.owner_handle) {
        tracing::warn!(
            identity = %identity.name,
            endpoint = "prf/disclose",
            "rejected disclose: owner handle does not match the stored owner tag"
        );
        return Err(AppError::Forbidden(
            "owner_handle does not match the entry owner",
        ));
    }
    let nullifier = prf.keys.disclose(&entry.value, &req.client_id);
    tracing::info!(identity = %identity.name, endpoint = "prf/disclose", "served");
    Ok(Json(DiscloseResponse { nullifier }))
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    /// base64url (no padding) of the 64-byte finalized VOPRF output N_dedup.
    pub value: String,
    /// The opaque per-user owner handle.
    pub owner_handle: String,
    /// The badge type slug this credential nullifies.
    pub badge_type: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    /// "registered" | "already_yours".
    pub status: &'static str,
    /// base64url (no padding) of the entry ref (existing one on already_yours).
    pub entry_ref: String,
}

/// POST /dedup/register — record-first UNIQUE(value) insert. Same value +
/// same owner -> already_yours (re-issue, same ref); different owner -> 409
/// taken (one-credential-one-account).
pub async fn dedup_register(
    State(state): State<Arc<AppState>>,
    identity: ClientIdentity,
    Json(req): Json<RegisterRequest>,
) -> AppResult<Json<RegisterResponse>> {
    let _prf = require_prf(&state, &identity)?;
    if req.value.is_empty() || req.value.len() > 96 {
        return Err(AppError::BadRequest("value length out of range"));
    }
    let value = b64url_decode(&req.value, "value is not valid base64url")?;
    if value.len() != prf::DEDUP_VALUE_LEN {
        return Err(AppError::BadRequest("value has the wrong length"));
    }
    validate_text(
        &req.owner_handle,
        MAX_OWNER_HANDLE_LEN,
        "owner_handle length out of range",
    )?;
    validate_text(
        &req.badge_type,
        MAX_BADGE_TYPE_LEN,
        "badge_type length out of range",
    )?;

    // Mint the candidate ref outside the DB call; on already_yours the stored
    // ref wins and this one is discarded.
    let mut entry_ref = [0u8; ENTRY_REF_LEN];
    use rand::TryRngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut entry_ref)
        .map_err(|e| AppError::Internal(format!("OS RNG failure: {e}")))?;

    let db = state.db.clone();
    let outcome = run_db_blocking(move || {
        db.register_dedup(&entry_ref, &value, &req.owner_handle, &req.badge_type)
    })
    .await?;
    // Logged uniformly for every outcome (registered / already_yours / taken):
    // the outcome goes only to the caller, never to the log stream.
    tracing::info!(identity = %identity.name, endpoint = "dedup/register", "served");
    let (status, entry_ref) = match outcome {
        DedupRegister::Registered { entry_ref } => ("registered", entry_ref),
        DedupRegister::AlreadyYours { entry_ref } => ("already_yours", entry_ref),
        DedupRegister::Taken => return Err(AppError::DedupTaken),
    };
    Ok(Json(RegisterResponse {
        status,
        entry_ref: B64URL.encode(entry_ref),
    }))
}

#[derive(Deserialize)]
pub struct ReleaseRequest {
    pub entry_ref: String,
    pub owner_handle: String,
}

#[derive(Serialize)]
pub struct ReleaseResponse {
    /// "released" | "already_released" (absent ref — idempotent retry).
    pub status: &'static str,
}

/// POST /dedup/release — owner-checked delete (badge revocation / account
/// deletion). Idempotent: releasing an already-released ref succeeds.
pub async fn dedup_release(
    State(state): State<Arc<AppState>>,
    identity: ClientIdentity,
    Json(req): Json<ReleaseRequest>,
) -> AppResult<Json<ReleaseResponse>> {
    let _prf = require_prf(&state, &identity)?;
    let entry_ref = decode_entry_ref(&req.entry_ref)?;
    validate_text(
        &req.owner_handle,
        MAX_OWNER_HANDLE_LEN,
        "owner_handle length out of range",
    )?;
    let db = state.db.clone();
    let outcome =
        run_db_blocking(move || db.release_dedup(&entry_ref, &req.owner_handle)).await?;
    // Uniform, outcome-free log line (see the module doc).
    tracing::info!(identity = %identity.name, endpoint = "dedup/release", "served");
    let status = match outcome {
        DedupRelease::Released => "released",
        DedupRelease::NotFound => "already_released",
        DedupRelease::OwnerMismatch => {
            tracing::warn!(
                identity = %identity.name,
                endpoint = "dedup/release",
                "rejected release: owner handle does not match the stored owner tag"
            );
            return Err(AppError::Forbidden(
                "owner_handle does not match the entry owner",
            ));
        }
    };
    Ok(Json(ReleaseResponse { status }))
}

#[derive(Deserialize)]
pub struct ReassignRequest {
    /// EXPLICIT list of entry refs to re-tag (never wholesale by owner).
    pub entry_refs: Vec<String>,
    pub from_owner_handle: String,
    pub to_owner_handle: String,
}

#[derive(Serialize)]
pub struct ReassignResponse {
    pub status: &'static str,
    /// Rows whose owner actually changed (already-target refs are no-ops).
    pub reassigned: usize,
}

/// POST /dedup/reassign — per-ref owner re-tag for account merge / reverse
/// merge. All-or-nothing: any ref owned by neither side rolls the whole batch
/// back (403), an unknown ref rolls back with 404. Retry-idempotent.
pub async fn dedup_reassign(
    State(state): State<Arc<AppState>>,
    identity: ClientIdentity,
    Json(req): Json<ReassignRequest>,
) -> AppResult<Json<ReassignResponse>> {
    let _prf = require_prf(&state, &identity)?;
    if req.entry_refs.is_empty() || req.entry_refs.len() > MAX_REASSIGN_REFS {
        return Err(AppError::BadRequest("entry_refs count out of range"));
    }
    let mut refs = Vec::with_capacity(req.entry_refs.len());
    for r in &req.entry_refs {
        refs.push(decode_entry_ref(r)?);
    }
    validate_text(
        &req.from_owner_handle,
        MAX_OWNER_HANDLE_LEN,
        "from_owner_handle length out of range",
    )?;
    validate_text(
        &req.to_owner_handle,
        MAX_OWNER_HANDLE_LEN,
        "to_owner_handle length out of range",
    )?;
    if req.from_owner_handle == req.to_owner_handle {
        return Err(AppError::BadRequest("from and to owner handles are equal"));
    }
    let db = state.db.clone();
    let outcome = run_db_blocking(move || {
        db.reassign_dedup(&refs, &req.from_owner_handle, &req.to_owner_handle)
    })
    .await?;
    let moved = match outcome {
        DedupReassign::Reassigned { moved } => moved,
        DedupReassign::NotFound => {
            return Err(AppError::NotFound("an entry_ref does not exist"));
        }
        DedupReassign::OwnerMismatch => {
            tracing::warn!(
                identity = %identity.name,
                endpoint = "dedup/reassign",
                "rejected reassign: an entry is owned by neither the source nor the target"
            );
            return Err(AppError::Forbidden(
                "an entry is owned by neither from_owner_handle nor to_owner_handle",
            ));
        }
    };
    tracing::info!(identity = %identity.name, endpoint = "dedup/reassign", "served");
    Ok(Json(ReassignResponse {
        status: "reassigned",
        reassigned: moved,
    }))
}
