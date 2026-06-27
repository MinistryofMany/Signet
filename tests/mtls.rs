//! mTLS access control and basic endpoint behavior over the real server.

mod common;
use common::*;

#[tokio::test]
async fn certless_client_is_rejected() {
    let pki = make_pki();
    let server = start_server(&pki, ServerOpts::default()).await;
    let client = client_without_cert(&pki);

    // No client cert -> the TLS handshake must fail; reqwest returns an error
    // rather than any HTTP response.
    let res = client
        .get(format!("{}/healthz", base_url(&server)))
        .send()
        .await;
    assert!(
        res.is_err(),
        "a client without a certificate must be rejected by mTLS, got {res:?}"
    );
}

#[tokio::test]
async fn client_with_cert_is_accepted() {
    let pki = make_pki();
    let server = start_server(&pki, ServerOpts::default()).await;
    let client = client_with_cert(&pki);

    let res = client
        .get(format!("{}/healthz", base_url(&server)))
        .send()
        .await
        .expect("authorized client should connect");
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn get_key_returns_spki() {
    let pki = make_pki();
    let server = start_server(&pki, ServerOpts::default()).await;
    let client = client_with_cert(&pki);
    let url = format!("{}/key?group_id=blog-1", base_url(&server));

    // Async keygen: the first GET enqueues and returns 202 pending; poll until
    // the key is ready, then assert the SPKI parses.
    let mut ready_body = None;
    for _ in 0..1200 {
        let res = client.get(&url).send().await.unwrap();
        let status = res.status();
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["group_id"], "blog-1");
        if status == 200 {
            assert_eq!(body["status"], "ready");
            ready_body = Some(body);
            break;
        }
        assert_eq!(status, 202, "expected ready or pending: {body}");
        assert_eq!(body["status"], "pending");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let body = ready_body.expect("key never became ready");
    let spki_b64 = body["public_key"].as_str().unwrap();
    let spki = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        spki_b64.as_bytes(),
    )
    .unwrap();
    // It must parse as a valid PBRSA public key.
    assert!(signet::crypto::public_key_from_spki(&spki).is_ok());
}
