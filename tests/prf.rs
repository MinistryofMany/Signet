//! PRF/dedup surface over the live mTLS HTTP service:
//!   - the Minister golden pairwise vectors reproduce byte-for-byte,
//!   - blind evaluate round-trips with a verifying DLEQ proof and finalizes
//!     to the frozen ecosystem N_dedup,
//!   - the dedup ledger enforces one-credential-one-account (incl. under
//!     concurrency), owner-checked release/reassign/disclose,
//!   - malformed input is a 400, never a 500.

mod common;
use common::*;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use serde_json::{json, Value};
use std::sync::Arc;
use voprf::{Group, Ristretto255, VoprfClient};

fn prf_server_opts() -> ServerOpts {
    ServerOpts {
        prf: Some(PrfOpts::default()),
        ..ServerOpts::default()
    }
}

async fn post(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    body: Value,
) -> (reqwest::StatusCode, Value) {
    let res = client
        .post(format!("{base}{path}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = res.status();
    let body: Value = res.json().await.unwrap();
    (status, body)
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("../interop/prf-vectors.json")).unwrap()
}

#[tokio::test]
async fn pairwise_reproduces_the_minister_golden_vectors() {
    let pki = make_pki();
    let server = start_server(&pki, prf_server_opts()).await;
    let client = prf_client(&pki);
    let base = base_url(&server);

    for vector in vectors()["pairwise"]["vectors"].as_array().unwrap() {
        let input = vector["input"].as_str().unwrap();
        let expected = vector["output"].as_str().unwrap();
        let (status, body) = post(&client, &base, "/prf/pairwise", json!({ "input": input })).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body["output"].as_str().unwrap(),
            expected,
            "pairwise output for {input:?} must be byte-identical to Minister's live path"
        );
    }
}

#[tokio::test]
async fn pairwise_without_imported_secret_is_404() {
    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            prf: Some(PrfOpts {
                pairwise_secret: None,
                ..PrfOpts::default()
            }),
            ..ServerOpts::default()
        },
    )
    .await;
    let client = prf_client(&pki);
    let (status, body) = post(
        &client,
        &base_url(&server),
        "/prf/pairwise",
        json!({ "input": "user:client" }),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"], "not_found");
}

#[tokio::test]
async fn evaluate_roundtrip_finalizes_to_the_frozen_n_dedup_with_verified_dleq() {
    let pki = make_pki();
    let server = start_server(&pki, prf_server_opts()).await;
    let client = prf_client(&pki);
    let base = base_url(&server);
    let vectors = vectors();

    // The pinned public key must match the frozen fixture.
    let res = client
        .get(format!("{base}/prf/public-key"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["suite"], "ristretto255-SHA512");
    let pk_b64 = body["public_key"].as_str().unwrap().to_string();
    assert_eq!(pk_b64, vectors["public_key_b64url"].as_str().unwrap());

    // Client-side blind (with a RANDOM blind) -> HTTP evaluate -> finalize.
    // Determinism of the finalized output regardless of the blind is exactly
    // what the dedup ledger relies on.
    let input = hex::decode(vectors["dedup"]["input_hex"].as_str().unwrap()).unwrap();
    let blind_result = VoprfClient::<Ristretto255>::blind(&input, &mut rand_core::OsRng).unwrap();
    let (status, body) = post(
        &client,
        &base,
        "/prf/evaluate",
        json!({ "blinded_element": B64URL.encode(blind_result.message.serialize()) }),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let eval_raw = B64URL
        .decode(body["evaluation_element"].as_str().unwrap())
        .unwrap();
    let proof_raw = B64URL.decode(body["proof"].as_str().unwrap()).unwrap();
    let eval = voprf::EvaluationElement::<Ristretto255>::deserialize(&eval_raw).unwrap();
    let proof = voprf::Proof::<Ristretto255>::deserialize(&proof_raw).unwrap();
    let pk_raw = B64URL.decode(&pk_b64).unwrap();
    let pk = <Ristretto255 as Group>::deserialize_elem(&pk_raw).unwrap();

    // finalize verifies the DLEQ proof against the pinned public key.
    let output = blind_result
        .state
        .finalize(&input, &eval, &proof, pk)
        .expect("finalize (incl. DLEQ verification) must succeed");
    assert_eq!(
        hex::encode(output),
        vectors["dedup"]["n_dedup_hex"].as_str().unwrap(),
        "finalized N_dedup must equal the frozen ecosystem vector"
    );

    // A proof tampered with by one byte must fail DLEQ verification.
    let mut bad_proof_raw = proof_raw.clone();
    bad_proof_raw[0] ^= 0x01;
    if let Ok(bad_proof) = voprf::Proof::<Ristretto255>::deserialize(&bad_proof_raw) {
        assert!(
            blind_result
                .state
                .finalize(&input, &eval, &bad_proof, pk)
                .is_err(),
            "a tampered DLEQ proof must not verify"
        );
    }
}

#[tokio::test]
async fn dedup_register_release_reassign_and_disclose_flow() {
    let pki = make_pki();
    let server = start_server(&pki, prf_server_opts()).await;
    let client = prf_client(&pki);
    let base = base_url(&server);
    let value = B64URL.encode([0x21u8; 64]);

    // Register.
    let (status, body) = post(
        &client,
        &base,
        "/dedup/register",
        json!({ "value": value, "owner_handle": "owner-a", "badge_type": "oauth-account" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "registered");
    let entry_ref = body["entry_ref"].as_str().unwrap().to_string();

    // Same owner re-register: already_yours with the SAME ref.
    let (status, body) = post(
        &client,
        &base,
        "/dedup/register",
        json!({ "value": value, "owner_handle": "owner-a", "badge_type": "oauth-account" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "already_yours");
    assert_eq!(body["entry_ref"].as_str().unwrap(), entry_ref);

    // Different owner: 409 taken.
    let (status, body) = post(
        &client,
        &base,
        "/dedup/register",
        json!({ "value": value, "owner_handle": "owner-b", "badge_type": "oauth-account" }),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "taken");

    // Disclose: owner-checked, per-RP distinct, deterministic, versioned.
    let (status, body) = post(
        &client,
        &base,
        "/prf/disclose",
        json!({ "entry_ref": entry_ref, "owner_handle": "owner-a", "client_id": "mc_rp_one" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let n_rp_one = body["nullifier"].as_str().unwrap().to_string();
    assert!(n_rp_one.starts_with("mnv1:"));
    let (_, body_again) = post(
        &client,
        &base,
        "/prf/disclose",
        json!({ "entry_ref": entry_ref, "owner_handle": "owner-a", "client_id": "mc_rp_one" }),
    )
    .await;
    assert_eq!(body_again["nullifier"].as_str().unwrap(), n_rp_one);
    let (_, body_two) = post(
        &client,
        &base,
        "/prf/disclose",
        json!({ "entry_ref": entry_ref, "owner_handle": "owner-a", "client_id": "mc_rp_two" }),
    )
    .await;
    assert_ne!(
        body_two["nullifier"].as_str().unwrap(),
        n_rp_one,
        "different RPs must receive unlinkable nullifiers"
    );

    // Disclose with the wrong owner handle: 403, fail closed.
    let (status, body) = post(
        &client,
        &base,
        "/prf/disclose",
        json!({ "entry_ref": entry_ref, "owner_handle": "owner-b", "client_id": "mc_rp_one" }),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "forbidden");

    // Reassign (merge): explicit ref list, owner-checked.
    let (status, body) = post(
        &client,
        &base,
        "/dedup/reassign",
        json!({
            "entry_refs": [entry_ref],
            "from_owner_handle": "owner-a",
            "to_owner_handle": "owner-b"
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["reassigned"], 1);
    // Disclosure now works for the new owner and yields the SAME per-RP value
    // (merge-invariant: the nullifier derives from the credential, not the
    // owner).
    let (status, body) = post(
        &client,
        &base,
        "/prf/disclose",
        json!({ "entry_ref": entry_ref, "owner_handle": "owner-b", "client_id": "mc_rp_one" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["nullifier"].as_str().unwrap(), n_rp_one);

    // Release with the wrong owner: 403; with the right owner: released.
    let (status, _) = post(
        &client,
        &base,
        "/dedup/release",
        json!({ "entry_ref": entry_ref, "owner_handle": "owner-a" }),
    )
    .await;
    assert_eq!(status, 403);
    let (status, body) = post(
        &client,
        &base,
        "/dedup/release",
        json!({ "entry_ref": entry_ref, "owner_handle": "owner-b" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "released");
    // Idempotent retry.
    let (status, body) = post(
        &client,
        &base,
        "/dedup/release",
        json!({ "entry_ref": entry_ref, "owner_handle": "owner-b" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "already_released");

    // After release the credential is registrable again (serial-identity
    // path: delete account -> re-verify from a new account succeeds).
    let (status, body) = post(
        &client,
        &base,
        "/dedup/register",
        json!({ "value": value, "owner_handle": "owner-c", "badge_type": "oauth-account" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "registered");
}

#[tokio::test]
async fn concurrent_register_same_value_has_exactly_one_winner() {
    let pki = make_pki();
    let server = start_server(&pki, prf_server_opts()).await;
    let client = Arc::new(prf_client(&pki));
    let base = base_url(&server);
    let value = B64URL.encode([0x77u8; 64]);

    let n = 16;
    let mut tasks = Vec::new();
    for i in 0..n {
        let client = client.clone();
        let base = base.clone();
        let value = value.clone();
        tasks.push(tokio::spawn(async move {
            let res = client
                .post(format!("{base}/dedup/register"))
                .json(&json!({
                    "value": value,
                    "owner_handle": format!("owner-{i}"),
                    "badge_type": "email-domain"
                }))
                .send()
                .await
                .unwrap();
            res.status().as_u16()
        }));
    }
    let mut ok = 0;
    let mut taken = 0;
    let mut other = 0;
    for t in tasks {
        match t.await.unwrap() {
            200 => ok += 1,
            409 => taken += 1,
            _ => other += 1,
        }
    }
    assert_eq!(ok, 1, "exactly one register may win");
    assert_eq!(taken, n - 1, "the rest must be 409 taken");
    assert_eq!(other, 0, "no other status allowed");
}

#[tokio::test]
async fn malformed_inputs_are_400_never_500() {
    let pki = make_pki();
    let server = start_server(&pki, prf_server_opts()).await;
    let client = prf_client(&pki);
    let base = base_url(&server);

    let cases: Vec<(&str, Value)> = vec![
        // pairwise: empty and oversize inputs.
        ("/prf/pairwise", json!({ "input": "" })),
        ("/prf/pairwise", json!({ "input": "x".repeat(513) })),
        // evaluate: bad base64, wrong length, non-canonical element, identity.
        (
            "/prf/evaluate",
            json!({ "blinded_element": "!!!not-base64!!!" }),
        ),
        (
            "/prf/evaluate",
            json!({ "blinded_element": B64URL.encode([0u8; 31]) }),
        ),
        (
            "/prf/evaluate",
            json!({ "blinded_element": B64URL.encode([0xffu8; 32]) }),
        ),
        (
            "/prf/evaluate",
            json!({ "blinded_element": B64URL.encode([0u8; 32]) }),
        ),
        ("/prf/evaluate", json!({ "blinded_element": "" })),
        // register: bad value encodings and oversize fields.
        (
            "/dedup/register",
            json!({ "value": "###", "owner_handle": "o", "badge_type": "t" }),
        ),
        (
            "/dedup/register",
            json!({ "value": B64URL.encode([0u8; 32]), "owner_handle": "o", "badge_type": "t" }),
        ),
        (
            "/dedup/register",
            json!({ "value": B64URL.encode([0u8; 64]), "owner_handle": "o".repeat(129), "badge_type": "t" }),
        ),
        (
            "/dedup/register",
            json!({ "value": B64URL.encode([0u8; 64]), "owner_handle": "o", "badge_type": "t".repeat(65) }),
        ),
        // disclose / release: bad refs.
        (
            "/prf/disclose",
            json!({ "entry_ref": "short", "owner_handle": "o", "client_id": "c" }),
        ),
        (
            "/prf/disclose",
            json!({ "entry_ref": B64URL.encode([0u8; 8]), "owner_handle": "o", "client_id": "c" }),
        ),
        (
            "/prf/disclose",
            json!({ "entry_ref": B64URL.encode([0u8; 16]), "owner_handle": "o", "client_id": "c".repeat(257) }),
        ),
        (
            "/dedup/release",
            json!({ "entry_ref": "%%%%", "owner_handle": "o" }),
        ),
        // reassign: empty list, oversize list, equal handles.
        (
            "/dedup/reassign",
            json!({ "entry_refs": [], "from_owner_handle": "a", "to_owner_handle": "b" }),
        ),
        (
            "/dedup/reassign",
            json!({
                "entry_refs": vec![B64URL.encode([0u8; 16]); 257],
                "from_owner_handle": "a",
                "to_owner_handle": "b"
            }),
        ),
        (
            "/dedup/reassign",
            json!({ "entry_refs": [B64URL.encode([0u8; 16])], "from_owner_handle": "a", "to_owner_handle": "a" }),
        ),
    ];

    for (path, body) in cases {
        let (status, resp) = post(&client, &base, path, body.clone()).await;
        assert_eq!(
            status, 400,
            "{path} with {body} must be 400, got {status}: {resp}"
        );
    }

    // Unknown refs: 404 (well-formed but absent).
    let absent = B64URL.encode([0xeeu8; 16]);
    let (status, _) = post(
        &client,
        &base,
        "/prf/disclose",
        json!({ "entry_ref": absent, "owner_handle": "o", "client_id": "c" }),
    )
    .await;
    assert_eq!(status, 404);
    let (status, _) = post(
        &client,
        &base,
        "/dedup/reassign",
        json!({ "entry_refs": [absent], "from_owner_handle": "a", "to_owner_handle": "b" }),
    )
    .await;
    assert_eq!(status, 404);
}
