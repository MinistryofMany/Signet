//! DoS / keygen-bound + client-identity tests (audit H1, M1, M3).
//!
//! These exercise, over the real mTLS HTTP service:
//!   - many concurrent `POST /key` for DISTINCT groups stay bounded and all
//!     eventually become ready (the worker pool caps concurrency rather than
//!     spawning unbounded multi-second keygens),
//!   - many concurrent `POST /key` for the SAME group are deduped to exactly one
//!     active key with no errors,
//!   - the `/key*` per-identity and global rate limits fire,
//!   - a cert that chains to the CA but is not on the client allow-list is
//!     rejected at the TLS layer (M1),
//!   - `/key/rotate` is admin-only: a non-admin client gets 403, the admin
//!     succeeds (M3).
//!
//! Keygen uses a small modulus here (these tests are about the worker pool and
//! access control, not the wire scheme; interop is proven separately at 2048).

mod common;
use common::*;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

const FAST_BITS: usize = 1024;

/// Poll `GET /key` until ready (200) or timeout. Returns the final status code.
async fn poll_until_ready(client: &reqwest::Client, base: &str, group: &str) -> bool {
    for _ in 0..600 {
        let res = client
            .get(format!("{base}/key?group_id={group}"))
            .send()
            .await
            .unwrap();
        if res.status() == 200 {
            let body: serde_json::Value = res.json().await.unwrap();
            assert_eq!(body["status"], "ready");
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

/// Many concurrent `POST /key` for DISTINCT groups: every request returns a
/// non-error status (200 ready or 202 pending) immediately, and every key
/// eventually becomes ready. The worker pool bounds concurrent keygen; the
/// requests themselves never block, so none time out or 5xx.
#[tokio::test]
async fn concurrent_distinct_group_keygen_is_bounded_and_nonblocking() {
    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            key_bits: FAST_BITS,
            keygen_max_concurrent: 2,
            // generous rate limits so the limiter does not mask the DoS bound
            rl_key_identity_max: 10_000,
            rl_key_global_max: 100_000,
            ..ServerOpts::default()
        },
    )
    .await;
    let client = Arc::new(client_with_cert(&pki));
    let base = base_url(&server);

    let n = 24;
    let groups: Vec<String> = (0..n).map(|i| format!("group-{i}")).collect();

    // Fire all POST /key concurrently. Each must return promptly with 200/202.
    let mut tasks = Vec::new();
    for g in &groups {
        let client = client.clone();
        let base = base.clone();
        let g = g.clone();
        tasks.push(tokio::spawn(async move {
            let res = client
                .post(format!("{base}/key?group_id={g}"))
                .send()
                .await
                .unwrap();
            res.status().as_u16()
        }));
    }
    for t in tasks {
        let code = t.await.unwrap();
        assert!(
            code == 200 || code == 202,
            "POST /key must enqueue (202) or be ready (200), got {code}"
        );
    }

    // Every distinct group's key eventually becomes ready.
    for g in &groups {
        assert!(
            poll_until_ready(&client, &base, g).await,
            "group {g} never became ready"
        );
    }
}

/// Many concurrent `POST /key` for the SAME group are deduped: no request
/// errors, and the group ends up with exactly one ready key.
#[tokio::test]
async fn concurrent_same_group_keygen_is_deduped() {
    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            key_bits: FAST_BITS,
            keygen_max_concurrent: 4,
            rl_key_identity_max: 10_000,
            rl_key_global_max: 100_000,
            ..ServerOpts::default()
        },
    )
    .await;
    let client = Arc::new(client_with_cert(&pki));
    let base = base_url(&server);

    let n = 32;
    let mut tasks = Vec::new();
    for _ in 0..n {
        let client = client.clone();
        let base = base.clone();
        tasks.push(tokio::spawn(async move {
            let res = client
                .post(format!("{base}/key?group_id=samegroup"))
                .send()
                .await
                .unwrap();
            res.status().as_u16()
        }));
    }
    let mut nonerror = 0;
    for t in tasks {
        let code = t.await.unwrap();
        assert!(code == 200 || code == 202, "unexpected status {code}");
        nonerror += 1;
    }
    assert_eq!(
        nonerror, n,
        "all concurrent same-group requests must be non-error"
    );

    assert!(poll_until_ready(&client, &base, "samegroup").await);

    // The key id must be stable across reads (one key, not many rotated ones):
    // fetch twice and compare key_id.
    let read_key_id = |client: Arc<reqwest::Client>, base: String| async move {
        let res = client
            .get(format!("{base}/key?group_id=samegroup"))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = res.json().await.unwrap();
        body["key_id"].as_i64().unwrap()
    };
    let a = read_key_id(client.clone(), base.clone()).await;
    let b = read_key_id(client.clone(), base.clone()).await;
    assert_eq!(a, b, "dedup must yield a single stable key id");
}

/// The `/key*` per-identity rate limit fires: with a low per-identity cap, the
/// first few requests are accepted and a later one is denied with 429.
#[tokio::test]
async fn key_endpoint_per_identity_rate_limit_fires() {
    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            key_bits: FAST_BITS,
            rl_key_identity_max: 3,
            rl_key_global_max: 10_000,
            ..ServerOpts::default()
        },
    )
    .await;
    let client = client_with_cert(&pki);
    let base = base_url(&server);

    // Three requests within budget (distinct groups so dedup does not matter).
    for i in 0..3 {
        let res = client
            .post(format!("{base}/key?group_id=rl-{i}"))
            .send()
            .await
            .unwrap();
        assert!(
            res.status() == 200 || res.status() == 202,
            "request {i} should be within budget"
        );
    }
    // Fourth exceeds the per-identity ceiling.
    let res = client
        .post(format!("{base}/key?group_id=rl-3"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 429, "per-identity /key rate limit must fire");
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "rate_limited");
}

/// The `/key*` global rate limit fires across identities.
#[tokio::test]
async fn key_endpoint_global_rate_limit_fires() {
    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            key_bits: FAST_BITS,
            rl_key_identity_max: 10_000,
            rl_key_global_max: 2,
            // allow both client and admin identities so we can spread requests
            allowed_client_ids: id_set(&[CLIENT_CN, ADMIN_CN]),
            admin_ids: id_set(&[ADMIN_CN]),
            ..ServerOpts::default()
        },
    )
    .await;
    let base = base_url(&server);

    let c1 = client_with_cert(&pki);
    let c2 = admin_client(&pki);

    let r1 = c1
        .post(format!("{base}/key?group_id=gg-1"))
        .send()
        .await
        .unwrap();
    assert!(r1.status() == 200 || r1.status() == 202);
    let r2 = c2
        .post(format!("{base}/key?group_id=gg-2"))
        .send()
        .await
        .unwrap();
    assert!(r2.status() == 200 || r2.status() == 202);
    // Global cap of 2 reached: a third request (either identity) is denied.
    let r3 = c1
        .post(format!("{base}/key?group_id=gg-3"))
        .send()
        .await
        .unwrap();
    assert_eq!(r3.status(), 429, "global /key rate limit must fire");
}

/// M1: a certificate that chains to the CA but is NOT on the configured client
/// allow-list is rejected at the TLS layer (the request errors, no HTTP).
#[tokio::test]
async fn unlisted_client_identity_is_rejected_at_connection() {
    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            key_bits: FAST_BITS,
            allowed_client_ids: id_set(&[CLIENT_CN]),
            admin_ids: id_set(&[ADMIN_CN]),
            ..ServerOpts::default()
        },
    )
    .await;
    let base = base_url(&server);

    // The allow-listed client connects fine.
    let ok = client_with_cert(&pki)
        .get(format!("{base}/healthz"))
        .send()
        .await;
    assert!(ok.is_ok(), "allow-listed client must connect: {ok:?}");

    // The "intruder" cert chains to the CA but is on no allow-list -> the
    // connection is dropped during/after the handshake; reqwest returns Err.
    let denied = other_client(&pki)
        .get(format!("{base}/healthz"))
        .send()
        .await;
    assert!(
        denied.is_err(),
        "a cert off the allow-list must be rejected at the connection, got {denied:?}"
    );
}

/// M3: `/key/rotate` is admin-only. A non-admin (but allow-listed) client is
/// forbidden (403); the admin identity succeeds and gets a fresh key.
#[tokio::test]
async fn rotate_requires_admin_identity() {
    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            key_bits: FAST_BITS,
            allowed_client_ids: id_set(&[CLIENT_CN, ADMIN_CN]),
            admin_ids: id_set(&[ADMIN_CN]),
            ..ServerOpts::default()
        },
    )
    .await;
    let base = base_url(&server);
    let client = client_with_cert(&pki);
    let admin = admin_client(&pki);

    // Create + ready a key first (as the non-admin client).
    let _ = client
        .post(format!("{base}/key?group_id=rot"))
        .send()
        .await
        .unwrap();
    assert!(poll_until_ready(&client, &base, "rot").await);
    let before: serde_json::Value = client
        .get(format!("{base}/key?group_id=rot"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key_id_before = before["key_id"].as_i64().unwrap();

    // Non-admin rotate -> 403 forbidden.
    let res = client
        .post(format!("{base}/key/rotate?group_id=rot"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "non-admin rotate must be forbidden");
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "forbidden");

    // Admin rotate -> 200 with a new key id.
    let res = admin
        .post(format!("{base}/key/rotate?group_id=rot"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "admin rotate must succeed");
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["status"], "ready");
    let key_id_after = body["key_id"].as_i64().unwrap();
    assert!(
        key_id_after > key_id_before,
        "rotation must mint a new key id ({key_id_after} > {key_id_before})"
    );
}

/// With no admin identity configured, `/key/rotate` is disabled for everyone
/// (fail-closed), even for an allow-listed client.
#[tokio::test]
async fn rotate_disabled_when_no_admin_configured() {
    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            key_bits: FAST_BITS,
            allowed_client_ids: id_set(&[CLIENT_CN]),
            admin_ids: BTreeSet::new(), // no admin -> rotation disabled
            ..ServerOpts::default()
        },
    )
    .await;
    let base = base_url(&server);
    let client = client_with_cert(&pki);

    let _ = client
        .post(format!("{base}/key?group_id=na"))
        .send()
        .await
        .unwrap();
    assert!(poll_until_ready(&client, &base, "na").await);

    let res = client
        .post(format!("{base}/key/rotate?group_id=na"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        403,
        "rotation must be forbidden when no admin identity is configured"
    );
}
