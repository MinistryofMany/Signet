//! Shared test harness: spins up the real mTLS server in-process against a
//! temp SQLite DB and dev certs generated with rcgen, and builds reqwest
//! clients with and without a client certificate.
//!
//! Each integration-test binary compiles this module independently and uses a
//! different subset of helpers, so per-binary "never used" warnings are
//! expected and silenced here.
#![allow(dead_code)]

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use signet::db::Db;
use signet::keystore::Kek;
use signet::ratelimit::RateLimiter;
use signet::state::AppState;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Once;

static INIT: Once = Once::new();

fn install_provider() {
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub struct Pki {
    pub ca_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

pub fn make_pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(vec![]).unwrap();
    ca.distinguished_name.push(DnType::CommonName, "Signet Test CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca.self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    let mut sp = CertificateParams::new(vec![]).unwrap();
    sp.distinguished_name.push(DnType::CommonName, "localhost");
    sp.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::IpAddress(Ipv4Addr::new(127, 0, 0, 1).into()),
    ];
    sp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = sp.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut cp = CertificateParams::new(vec![]).unwrap();
    cp.distinguished_name.push(DnType::CommonName, "freedink");
    cp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = cp.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

    Pki {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

pub struct Server {
    pub addr: SocketAddr,
    pub db_path: std::path::PathBuf,
    _tmp: tempfile::TempDir,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Configuration knobs for the test server.
pub struct ServerOpts {
    pub rl_participant_max: u32,
    pub rl_global_max: u32,
    pub key_bits: usize,
}

impl Default for ServerOpts {
    fn default() -> Self {
        // 2048 is required for TS interop, but unit/integration tests that do
        // not check interop can use a smaller modulus to keep keygen fast.
        Self {
            rl_participant_max: 100,
            rl_global_max: 10_000,
            key_bits: 2048,
        }
    }
}

/// Start the real mTLS server on an ephemeral port. Returns once the listener
/// is accepting. Writes dev certs into the temp dir.
pub async fn start_server(pki: &Pki, opts: ServerOpts) -> Server {
    install_provider();
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("signet.db");

    // Write certs to temp files for the TLS loader.
    let ca_path = tmp.path().join("ca.pem");
    let cert_path = tmp.path().join("server.pem");
    let key_path = tmp.path().join("server.key");
    std::fs::write(&ca_path, &pki.ca_pem).unwrap();
    std::fs::write(&cert_path, &pki.server_cert_pem).unwrap();
    std::fs::write(&key_path, &pki.server_key_pem).unwrap();

    let kek = Kek::from_encoded(&hex::encode([0x5au8; 32])).unwrap();
    let db = Db::open(&db_path).unwrap();
    let state = Arc::new(AppState {
        db,
        kek,
        rate_limiter: RateLimiter::new(opts.rl_participant_max, opts.rl_global_max, 60),
        auto_create_keys: true,
        key_bits: opts.key_bits,
    });
    let app = signet::router(state);

    let tls = signet::tls::build_server_config(&cert_path, &key_path, &ca_path).unwrap();
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(tls);

    // Bind an ephemeral port via std, learn the addr, then hand to axum-server.
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, rustls_config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    // Wait for the port to accept TLS handshakes.
    for _ in 0..100 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    Server {
        addr,
        db_path,
        _tmp: tmp,
        handle,
    }
}

/// A reqwest client that presents the client certificate (authorized).
pub fn client_with_cert(pki: &Pki) -> reqwest::Client {
    let mut identity_pem = pki.client_cert_pem.clone();
    identity_pem.push_str(&pki.client_key_pem);
    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap();
    let ca = reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap();
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca)
        .identity(identity)
        .build()
        .unwrap()
}

/// A reqwest client with NO client certificate (should be rejected by mTLS).
pub fn client_without_cert(pki: &Pki) -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap();
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca)
        .build()
        .unwrap()
}

pub fn base_url(server: &Server) -> String {
    format!("https://localhost:{}", server.addr.port())
}
