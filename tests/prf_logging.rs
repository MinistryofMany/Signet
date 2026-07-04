//! No-log assertions for the PRF surface: with a real global tracing
//! subscriber capturing everything the server emits, drive every PRF/dedup
//! endpoint (success AND failure paths) and assert the log stream contains
//! identities/endpoints but NEVER inputs, outputs, values, nullifiers, owner
//! handles, or entry refs.
//!
//! This file is its own integration-test binary with exactly one test, so the
//! global subscriber cannot interfere with other tests.

mod common;
use common::*;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use serde_json::json;
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn prf_logs_carry_identity_and_endpoint_but_never_payloads() {
    let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    let writer_buf = buf.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer_buf.clone())
        .init();

    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            prf: Some(PrfOpts::default()),
            allowed_client_ids: id_set(&[CLIENT_CN]),
            ..ServerOpts::default()
        },
    )
    .await;
    let client = prf_client(&pki);
    let base = base_url(&server);

    // Distinctive payload markers that must never appear in logs.
    let pairwise_input = "SECRET-PAIRWISE-INPUT-user_zz91:mc_zz91";
    let owner_a = "OWNER-HANDLE-SECRET-A-zz91";
    let owner_b = "OWNER-HANDLE-SECRET-B-zz91";
    let client_id = "mc_SECRET_CLIENT_zz91";
    let value_bytes = [0xd7u8; 64];
    let value_b64 = B64URL.encode(value_bytes);

    // Success paths.
    let res = client
        .post(format!("{base}/prf/pairwise"))
        .json(&json!({ "input": pairwise_input }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let pairwise_output = res.json::<serde_json::Value>().await.unwrap()["output"]
        .as_str()
        .unwrap()
        .to_string();

    let res = client
        .post(format!("{base}/dedup/register"))
        .json(&json!({ "value": value_b64, "owner_handle": owner_a, "badge_type": "email-domain" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let entry_ref = res.json::<serde_json::Value>().await.unwrap()["entry_ref"]
        .as_str()
        .unwrap()
        .to_string();

    let res = client
        .post(format!("{base}/prf/disclose"))
        .json(&json!({ "entry_ref": entry_ref, "owner_handle": owner_a, "client_id": client_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let nullifier = res.json::<serde_json::Value>().await.unwrap()["nullifier"]
        .as_str()
        .unwrap()
        .to_string();

    // already_yours re-register: its log line must carry no outcome status.
    let res = client
        .post(format!("{base}/dedup/register"))
        .json(&json!({ "value": value_b64, "owner_handle": owner_a, "badge_type": "email-domain" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Failure paths (owner mismatch + taken + authz refusal) — the warn/info
    // lines they emit must be payload-free too.
    let res = client
        .post(format!("{base}/prf/disclose"))
        .json(&json!({ "entry_ref": entry_ref, "owner_handle": owner_b, "client_id": client_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let res = client
        .post(format!("{base}/dedup/register"))
        .json(&json!({ "value": value_b64, "owner_handle": owner_b, "badge_type": "email-domain" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409);
    let freedink = client_with_cert(&pki);
    let res = freedink
        .post(format!("{base}/prf/pairwise"))
        .json(&json!({ "input": pairwise_input }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Release + idempotent retry (released / already_released outcomes) — run
    // last so the entry_ref stays live for the paths above.
    for _ in 0..2 {
        let res = client
            .post(format!("{base}/dedup/release"))
            .json(&json!({ "entry_ref": entry_ref, "owner_handle": owner_a }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
    }

    let logs = String::from_utf8_lossy(&buf.0.lock().unwrap()).to_string();

    // Sanity: the capture works and carries identity + endpoint.
    assert!(
        logs.contains("prf/pairwise"),
        "expected endpoint names in the captured logs; capture broken?"
    );
    assert!(
        logs.contains(PRF_CN),
        "expected the pinned identity in logs"
    );

    // The forbidden strings: inputs, outputs, handles, refs, values.
    for (what, needle) in [
        ("pairwise input", pairwise_input),
        ("pairwise output", pairwise_output.as_str()),
        ("owner handle A", owner_a),
        ("owner handle B", owner_b),
        ("client_id", client_id),
        ("entry_ref", entry_ref.as_str()),
        ("dedup value (b64)", value_b64.as_str()),
        ("disclosed nullifier", nullifier.as_str()),
    ] {
        assert!(
            !logs.contains(needle),
            "{what} leaked into the logs: {needle}"
        );
    }
    // Hex spellings of the dedup value must not appear either.
    assert!(!logs.contains(&hex::encode(value_bytes)));

    // Per-request OUTCOME status must not appear: a log reader must not be
    // able to see credential-collision events ("taken") or distinguish
    // registered/already_yours/released/already_released from the stream.
    for outcome in ["status=", "taken", "already_yours", "already_released"] {
        assert!(
            !logs.contains(outcome),
            "outcome marker {outcome:?} leaked into the logs"
        );
    }
}
