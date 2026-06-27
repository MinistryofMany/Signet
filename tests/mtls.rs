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

    let res = client
        .get(format!("{}/key?group_id=blog-1", base_url(&server)))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["group_id"], "blog-1");
    let spki_b64 = body["public_key"].as_str().unwrap();
    let spki = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        spki_b64.as_bytes(),
    )
    .unwrap();
    // It must parse as a valid PBRSA public key.
    assert!(signet::crypto::public_key_from_spki(&spki).is_ok());
}
