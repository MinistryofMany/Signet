//! Private-key-at-rest: the DB must contain only AES-GCM ciphertext for the
//! private key, never plaintext PKCS#8.

mod common;
use common::*;

use rusqlite::Connection;

/// The DER prefix of an unencrypted PKCS#8 RSA private key: a SEQUENCE, then
/// INTEGER version 0, then the rsaEncryption AlgorithmIdentifier OID
/// (1.2.840.113549.1.1.1 = 2a 86 48 86 f7 0d 01 01 01). If any stored blob
/// contains this, the key leaked in plaintext.
const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const PKCS8_VERSION_INTEGER: &[u8] = &[0x02, 0x01, 0x00]; // INTEGER 0

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn private_key_is_ciphertext_at_rest() {
    let pki = make_pki();
    let server = start_server(&pki, ServerOpts::default()).await;
    let client = client_with_cert(&pki);
    let base = base_url(&server);

    // Create a couple of group keys so the DB has key rows to inspect. Key
    // creation is now async: POST enqueues (202 pending), so poll GET until the
    // key is ready before opening the DB.
    for g in ["blog-a", "blog-b"] {
        let res = client
            .post(format!("{base}/key?group_id={g}"))
            .send()
            .await
            .unwrap();
        assert!(
            res.status() == 202 || res.status() == 200,
            "POST /key should enqueue (202) or be already-ready (200)"
        );
        // Poll until ready. Ceiling 3600 x 100ms ~ 360s: 2048-bit safe-prime
        // keygen is high-variance and a single key has taken ~50s on a slow
        // shared CI runner; the poll exits as soon as the key is ready.
        let mut ready = false;
        for _ in 0..3600 {
            let res = client
                .get(format!("{base}/key?group_id={g}"))
                .send()
                .await
                .unwrap();
            let status = res.status();
            let body: serde_json::Value = res.json().await.unwrap();
            if status == 200 {
                assert_eq!(body["status"], "ready");
                ready = true;
                break;
            }
            assert_eq!(status, 202, "expected ready or pending: {body}");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(ready, "key for {g} never became ready");
    }

    // Open the SQLite file directly and inspect the stored private-key blobs.
    let conn = Connection::open(&server.db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT group_id, sealed_pkcs8 FROM group_keys")
        .unwrap();
    let rows: Vec<(String, Vec<u8>)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    assert!(!rows.is_empty(), "expected stored keys to inspect");

    for (group, blob) in &rows {
        // The blob must start with our AES-GCM envelope version byte, not a DER
        // SEQUENCE tag (0x30).
        assert_eq!(
            blob[0], 0x01,
            "blob for {group} must be our sealed envelope (v1), not raw DER"
        );
        assert_ne!(
            blob[0], 0x30,
            "blob for {group} starts with a DER SEQUENCE tag"
        );
        // No plaintext PKCS#8 structural markers may appear anywhere in the blob.
        assert!(
            !contains(blob, RSA_OID),
            "blob for {group} contains the rsaEncryption OID (plaintext key leak)"
        );
        assert!(
            !(blob.len() > 4 && contains(&blob[..6.min(blob.len())], PKCS8_VERSION_INTEGER)),
            "blob for {group} begins like a PKCS#8 structure"
        );
    }

    // Sanity: a freshly generated plaintext key DOES contain the OID, proving
    // the check above is meaningful (not vacuously true).
    let fresh = signet::crypto::generate_group_key(2048).unwrap();
    assert!(
        contains(&fresh.pkcs8_der, RSA_OID),
        "control: plaintext PKCS#8 should contain the rsaEncryption OID"
    );
}

#[tokio::test]
async fn service_keys_are_ciphertext_at_rest() {
    // The PRF service keys (master seed + imported pairwise secret) must be
    // stored ONLY as KEK-sealed AES-GCM envelopes: neither the fixed test
    // seed bytes nor the pairwise secret bytes may appear anywhere in the
    // database file's service_keys rows.
    let pki = make_pki();
    let seed = *b"MINISTER-TEST-VECTOR-SEED-0001!!";
    let pairwise = b"minister-golden-vector-secret-v1-do-not-change!!".to_vec();
    let server = start_server(
        &pki,
        ServerOpts {
            prf: Some(PrfOpts {
                master_seed: seed,
                pairwise_secret: Some(pairwise.clone()),
                ..PrfOpts::default()
            }),
            ..ServerOpts::default()
        },
    )
    .await;

    let conn = Connection::open(&server.db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT purpose, sealed FROM service_keys")
        .unwrap();
    let rows: Vec<(String, Vec<u8>)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let purposes: Vec<&str> = rows.iter().map(|(p, _)| p.as_str()).collect();
    assert!(purposes.contains(&"master-seed-v1"), "seed row present");
    assert!(
        purposes.contains(&"pairwise-hmac-v1"),
        "pairwise row present"
    );

    for (purpose, blob) in &rows {
        assert_eq!(
            blob[0], 0x01,
            "service key {purpose} must be our sealed envelope (v1)"
        );
        assert!(
            !contains(blob, &seed),
            "service key {purpose} contains the plaintext master seed"
        );
        assert!(
            !contains(blob, &pairwise),
            "service key {purpose} contains the plaintext pairwise secret"
        );
        // No long plaintext substring either (a partial leak is still a leak).
        assert!(
            !contains(blob, &seed[..16]),
            "service key {purpose} contains a seed prefix"
        );
        assert!(
            !contains(blob, &pairwise[..16]),
            "service key {purpose} contains a pairwise-secret prefix"
        );
    }

    // Control: the check is meaningful — the seed does contain its own prefix.
    assert!(contains(&seed, &seed[..16]));
}
