//! PRF surface authorization, fail-closed at every layer:
//!   - a /sign-authorized identity NOT on SIGNET_PRF_CLIENT_IDS gets 403 on
//!     EVERY /prf/* and /dedup/* route,
//!   - a PRF-only identity gets 403 on the blind-RSA surface,
//!   - without PRF configuration the routes are not even mounted (404) and
//!     /sign works exactly as before,
//!   - startup refusals (empty-list / seed-absent / pin-mismatch) are pinned
//!     at the boot-policy level in src/dedup.rs unit tests.

mod common;
use common::*;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use serde_json::json;

/// Every PRF/dedup route with a syntactically valid body, so the ONLY thing
/// that can reject the request is authorization.
fn prf_routes() -> Vec<(&'static str, &'static str, serde_json::Value)> {
    let entry_ref = B64URL.encode([0u8; 16]);
    vec![
        ("POST", "/prf/pairwise", json!({ "input": "user:client" })),
        (
            "POST",
            "/prf/evaluate",
            json!({ "blinded_element": B64URL.encode([0u8; 32]) }),
        ),
        ("GET", "/prf/public-key", json!({})),
        (
            "POST",
            "/prf/disclose",
            json!({ "entry_ref": entry_ref, "owner_handle": "o", "client_id": "c" }),
        ),
        (
            "POST",
            "/dedup/register",
            json!({ "value": B64URL.encode([0u8; 64]), "owner_handle": "o", "badge_type": "t" }),
        ),
        (
            "POST",
            "/dedup/release",
            json!({ "entry_ref": entry_ref, "owner_handle": "o" }),
        ),
        (
            "POST",
            "/dedup/reassign",
            json!({ "entry_refs": [entry_ref], "from_owner_handle": "a", "to_owner_handle": "b" }),
        ),
    ]
}

async fn status_for(
    client: &reqwest::Client,
    base: &str,
    method: &str,
    path: &str,
    body: &serde_json::Value,
) -> u16 {
    let req = match method {
        "GET" => client.get(format!("{base}{path}")),
        _ => client.post(format!("{base}{path}")).json(body),
    };
    req.send().await.unwrap().status().as_u16()
}

#[tokio::test]
async fn sign_authorized_identity_gets_403_on_every_prf_route() {
    let pki = make_pki();
    // freedink is on the client allow-list (may /sign) but NOT on the PRF
    // list; minister is PRF-only.
    let server = start_server(
        &pki,
        ServerOpts {
            allowed_client_ids: id_set(&[CLIENT_CN]),
            prf: Some(PrfOpts::default()),
            ..ServerOpts::default()
        },
    )
    .await;
    let base = base_url(&server);
    let freedink = client_with_cert(&pki);
    for (method, path, body) in prf_routes() {
        assert_eq!(
            status_for(&freedink, &base, method, path, &body).await,
            403,
            "{path} must be 403 for a /sign-authorized, non-PRF identity"
        );
    }
}

#[tokio::test]
async fn open_client_list_still_does_not_grant_prf() {
    let pki = make_pki();
    // OPEN client list (back-compat: any valid-chain cert may /sign) — the
    // PRF surface must STILL refuse identities off the PRF list.
    let server = start_server(
        &pki,
        ServerOpts {
            allowed_client_ids: id_set(&[]),
            prf: Some(PrfOpts::default()),
            ..ServerOpts::default()
        },
    )
    .await;
    let base = base_url(&server);
    let intruder = other_client(&pki);
    for (method, path, body) in prf_routes() {
        assert_eq!(
            status_for(&intruder, &base, method, path, &body).await,
            403,
            "{path} must be 403 under the open client list"
        );
    }
}

#[tokio::test]
async fn san_smuggled_prf_grant_with_a_foreign_pinned_name_is_refused() {
    let pki = make_pki();
    // OPEN client list: the smuggling cert (CN "sneaky-rp", DNS SAN
    // "minister") is admitted as a Client and classify pins its CN as the
    // identity name, while the stray SAN sets the prf_allowed flag. The
    // in-handler second-layer check must refuse every PRF/dedup route: the
    // PINNED (audited) name is not itself on SIGNET_PRF_CLIENT_IDS.
    let server = start_server(
        &pki,
        ServerOpts {
            allowed_client_ids: id_set(&[]),
            prf: Some(PrfOpts::default()),
            ..ServerOpts::default()
        },
    )
    .await;
    let base = base_url(&server);
    let smuggler = san_smuggle_client(&pki);
    for (method, path, body) in prf_routes() {
        assert_eq!(
            status_for(&smuggler, &base, method, path, &body).await,
            403,
            "{path} must be 403 when the pinned name is not the PRF-listed one"
        );
    }
    // The genuine PRF identity (pinned name == PRF-listed name) still passes.
    let minister = prf_client(&pki);
    let res = minister
        .get(format!("{base}/prf/public-key"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn prf_only_identity_is_refused_on_the_blind_rsa_surface() {
    let pki = make_pki();
    let server = start_server(
        &pki,
        ServerOpts {
            allowed_client_ids: id_set(&[CLIENT_CN]),
            prf: Some(PrfOpts::default()),
            ..ServerOpts::default()
        },
    )
    .await;
    let base = base_url(&server);
    let minister = prf_client(&pki);

    // The PRF surface serves it…
    let res = minister
        .get(format!("{base}/prf/public-key"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // …but /sign and /key* refuse it.
    let res = minister
        .post(format!("{base}/sign"))
        .json(&json!({
            "group_id": "g", "participant_id": "p", "version_id": "v",
            "blinded_message": "AAAA"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "PRF-only identity must not reach /sign");
    let res = minister
        .get(format!("{base}/key?group_id=g"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "PRF-only identity must not reach /key");
    let res = minister
        .post(format!("{base}/key/rotate?group_id=g"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
}

#[tokio::test]
async fn identity_on_both_lists_reaches_both_surfaces() {
    let pki = make_pki();
    let prf = PrfOpts {
        client_ids: id_set(&[PRF_CN, CLIENT_CN]),
        ..PrfOpts::default()
    };
    let server = start_server(
        &pki,
        ServerOpts {
            allowed_client_ids: id_set(&[CLIENT_CN]),
            prf: Some(prf),
            ..ServerOpts::default()
        },
    )
    .await;
    let base = base_url(&server);
    let freedink = client_with_cert(&pki);
    // PRF surface: allowed (on the PRF list).
    let res = freedink
        .get(format!("{base}/prf/public-key"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    // Blind-RSA surface: allowed (on the client list). /key GET enqueues.
    let res = freedink
        .get(format!("{base}/key?group_id=g1"))
        .send()
        .await
        .unwrap();
    assert!(
        res.status() == 200 || res.status() == 202,
        "client-listed identity must reach /key, got {}",
        res.status()
    );
}

#[tokio::test]
async fn without_prf_config_routes_are_not_mounted_and_sign_is_unchanged() {
    let pki = make_pki();
    let server = start_server(&pki, ServerOpts::default()).await; // no PRF
    let base = base_url(&server);
    let client = client_with_cert(&pki);

    for (method, path, body) in prf_routes() {
        assert_eq!(
            status_for(&client, &base, method, path, &body).await,
            404,
            "{path} must be unmounted (404) without PRF configuration"
        );
    }
    // The pre-PRF surface is intact.
    let res = client.get(format!("{base}/healthz")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let res = client
        .get(format!("{base}/key?group_id=blog-1"))
        .send()
        .await
        .unwrap();
    assert!(res.status() == 200 || res.status() == 202);
}

#[tokio::test]
async fn prf_rate_limit_bucket_is_separate_and_fires() {
    let pki = make_pki();
    let prf = PrfOpts {
        rl_identity_max: 2,
        ..PrfOpts::default()
    };
    let server = start_server(
        &pki,
        ServerOpts {
            prf: Some(prf),
            ..ServerOpts::default()
        },
    )
    .await;
    let base = base_url(&server);
    let minister = prf_client(&pki);
    for _ in 0..2 {
        let res = minister
            .get(format!("{base}/prf/public-key"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
    }
    let res = minister
        .get(format!("{base}/prf/public-key"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 429, "the PRF bucket must fire on the third");
}
