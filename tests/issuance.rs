//! Issuance invariants over the live mTLS HTTP service:
//!   - exactly one signature per (group, participant, version), incl. under
//!     concurrency,
//!   - rate limiting fires (per-participant and global),
//!   - a signed token verifies, and a v1 token does NOT verify under v2.
//!
//! Verification uses the crate's own client primitives (blind/finalize/verify),
//! which the `interop/` harness proves are byte-compatible with the TS verifier
//! FreedInk runs.

mod common;
use common::*;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blind_rsa_signatures::pbrsa::{DefaultRng, PartiallyBlindPublicKey};
use blind_rsa_signatures::{BlindSignature, Randomized, Sha384, PSS};
use serde_json::json;
use std::sync::Arc;

type PubKey = PartiallyBlindPublicKey<Sha384, PSS, Randomized>;

fn info(version: &str) -> Vec<u8> {
    signet::crypto::version_info(version)
}

async fn fetch_pubkey(client: &reqwest::Client, base: &str, group: &str) -> PubKey {
    let res = client
        .get(format!("{base}/key?group_id={group}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    let spki = B64.decode(body["public_key"].as_str().unwrap()).unwrap();
    signet::crypto::public_key_from_spki(&spki).unwrap()
}

/// Run a full issuance: blind a nonce client-side, POST /sign, return the
/// HTTP response together with the blinding state needed to finalize.
///
/// `pk` is the MASTER public key from `GET /key`. Mirroring how a client uses
/// this crate, we derive the per-metadata public key and blind against THAT
/// (the crate's `blind()` does not derive internally — the metadata arg only
/// feeds the message hash, so the RSA blinding must use the derived exponent).
async fn request_sign(
    client: &reqwest::Client,
    base: &str,
    pk: &PubKey,
    group: &str,
    participant: &str,
    version: &str,
) -> (reqwest::StatusCode, serde_json::Value, Option<FinalizeState>) {
    let info = info(version);
    let derived_pk = pk.derive_public_key_for_metadata(&info).unwrap();
    let nonce = b"token-nonce-0123456789abcdef0123";
    let blinding = derived_pk
        .blind(&mut DefaultRng, nonce, Some(&info))
        .unwrap();
    let blinded_b64 = B64.encode(&blinding.blind_message.0);

    let res = client
        .post(format!("{base}/sign"))
        .json(&json!({
            "group_id": group,
            "participant_id": participant,
            "version_id": version,
            "blinded_message": blinded_b64,
        }))
        .send()
        .await
        .unwrap();
    let status = res.status();
    let body: serde_json::Value = res.json().await.unwrap();
    let state = if status == 200 {
        Some(FinalizeState {
            derived_pk,
            blinding,
            nonce: nonce.to_vec(),
        })
    } else {
        None
    };
    (status, body, state)
}

struct FinalizeState {
    derived_pk: PubKey,
    blinding: blind_rsa_signatures::BlindingResult,
    nonce: Vec<u8>,
}

#[tokio::test]
async fn one_signature_per_tuple() {
    let pki = make_pki();
    let server = start_server(&pki, ServerOpts::default()).await;
    let client = client_with_cert(&pki);
    let base = base_url(&server);
    let pk = fetch_pubkey(&client, &base, "g1").await;

    let (s1, b1, st1) = request_sign(&client, &base, &pk, "g1", "alice", "v1").await;
    assert_eq!(s1, 200, "first issuance must succeed: {b1}");
    assert!(st1.is_some());

    // Second request for the SAME tuple must be rejected as already issued.
    let (s2, b2, _) = request_sign(&client, &base, &pk, "g1", "alice", "v1").await;
    assert_eq!(s2, 409, "duplicate tuple must be 409: {b2}");
    assert_eq!(b2["error"], "already_issued");

    // A different version for the same participant is allowed.
    let (s3, _b3, _) = request_sign(&client, &base, &pk, "g1", "alice", "v2").await;
    assert_eq!(s3, 200, "different version must succeed");
}

#[tokio::test]
async fn signed_token_verifies_and_cross_version_fails() {
    let pki = make_pki();
    let server = start_server(&pki, ServerOpts::default()).await;
    let client = client_with_cert(&pki);
    let base = base_url(&server);
    let pk = fetch_pubkey(&client, &base, "g1").await;

    let (status, body, state) = request_sign(&client, &base, &pk, "g1", "bob", "v1").await;
    assert_eq!(status, 200, "{body}");
    let state = state.unwrap();

    let blind_sig = B64.decode(body["blind_signature"].as_str().unwrap()).unwrap();
    let blind_sig = BlindSignature(blind_sig);

    // Finalize + verify under v1 (against the v1-derived public key): success.
    let info_v1 = info("v1");
    let sig = state
        .derived_pk
        .finalize(&blind_sig, &state.blinding, &state.nonce, Some(&info_v1))
        .expect("v1 token must finalize");
    state
        .derived_pk
        .verify(&sig, state.blinding.msg_randomizer, &state.nonce, Some(&info_v1))
        .expect("v1 token must verify under v1");

    // The same signature must NOT verify under v2 metadata (cross-version
    // binding): verify against the v2-derived public key — must fail.
    let info_v2 = info("v2");
    let derived_v2 = pk.derive_public_key_for_metadata(&info_v2).unwrap();
    assert!(
        derived_v2
            .verify(&sig, state.blinding.msg_randomizer, &state.nonce, Some(&info_v2))
            .is_err(),
        "v1 token must not verify under v2 metadata"
    );
}

#[tokio::test]
async fn participant_rate_limit_fires() {
    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            rl_participant_max: 2,
            rl_global_max: 10_000,
            key_bits: 2048,
        },
    )
    .await;
    let client = client_with_cert(&pki);
    let base = base_url(&server);
    let pk = fetch_pubkey(&client, &base, "g1").await;

    // Two distinct versions succeed (each is a unique tuple).
    for v in ["v1", "v2"] {
        let (s, b, _) = request_sign(&client, &base, &pk, "g1", "carol", v).await;
        assert_eq!(s, 200, "{b}");
    }
    // Third distinct version is blocked by the participant ceiling (2/window).
    let (s, b, _) = request_sign(&client, &base, &pk, "g1", "carol", "v3").await;
    assert_eq!(s, 429, "participant rate limit must fire: {b}");
    assert_eq!(b["error"], "rate_limited");
}

#[tokio::test]
async fn global_rate_limit_fires() {
    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            rl_participant_max: 1000,
            rl_global_max: 2,
            key_bits: 2048,
        },
    )
    .await;
    let client = client_with_cert(&pki);
    let base = base_url(&server);
    let pk = fetch_pubkey(&client, &base, "g1").await;

    let (a, _, _) = request_sign(&client, &base, &pk, "g1", "p1", "v1").await;
    let (b, _, _) = request_sign(&client, &base, &pk, "g1", "p2", "v1").await;
    assert_eq!(a, 200);
    assert_eq!(b, 200);
    // Global ceiling of 2 reached; a fresh participant is denied.
    let (c, body, _) = request_sign(&client, &base, &pk, "g1", "p3", "v1").await;
    assert_eq!(c, 429, "global rate limit must fire: {body}");
}

#[tokio::test]
async fn concurrent_same_tuple_yields_exactly_one_success() {
    let pki = make_pki();
    let server = start_server(&pki, ServerOpts::default()).await;
    let client = Arc::new(client_with_cert(&pki));
    let base = base_url(&server);
    let pk = Arc::new(fetch_pubkey(&client, &base, "g1").await);

    // Fire many concurrent /sign for the identical (group, participant, version).
    // Exactly one must get a 200; the rest must be 409 already_issued. None may
    // be a 5xx or a second successful signature.
    let n = 16;
    let mut tasks = Vec::new();
    for _ in 0..n {
        let client = client.clone();
        let pk = pk.clone();
        let base = base.clone();
        tasks.push(tokio::spawn(async move {
            let info = info("v1");
            let derived_pk = pk.derive_public_key_for_metadata(&info).unwrap();
            let nonce = b"concurrent-nonce-aaaaaaaaaaaaaaaa";
            let blinding = derived_pk
                .blind(&mut DefaultRng, nonce, Some(&info))
                .unwrap();
            let blinded_b64 = B64.encode(&blinding.blind_message.0);
            let res = client
                .post(format!("{base}/sign"))
                .json(&json!({
                    "group_id": "g1",
                    "participant_id": "dave",
                    "version_id": "v1",
                    "blinded_message": blinded_b64,
                }))
                .send()
                .await
                .unwrap();
            res.status().as_u16()
        }));
    }

    let mut ok = 0;
    let mut conflict = 0;
    let mut other = 0;
    for t in tasks {
        match t.await.unwrap() {
            200 => ok += 1,
            409 => conflict += 1,
            _ => other += 1,
        }
    }
    assert_eq!(ok, 1, "exactly one signature may be issued, got {ok}");
    assert_eq!(conflict, n - 1, "the rest must be 409, got {conflict}");
    assert_eq!(other, 0, "no other status allowed, got {other}");
}
