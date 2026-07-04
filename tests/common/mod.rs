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
use signet::dedup::{prepare_prf_boot, PrfBoot, PrfBootArgs};
use signet::identity::IdentityPolicy;
use signet::keygen::KeygenService;
use signet::keystore::Kek;
use signet::ratelimit::{KeyRateLimiter, RateLimiter};
use signet::state::{AppState, PrfState};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Once;
use zeroize::Zeroizing;

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
    /// Default client identity: CN "freedink".
    pub client_cert_pem: String,
    pub client_key_pem: String,
    /// Admin client identity: CN "signet-admin".
    pub admin_cert_pem: String,
    pub admin_key_pem: String,
    /// A second non-admin client identity: CN "intruder" (used to prove a cert
    /// that chains to the CA but is off the allow-list is rejected).
    pub other_cert_pem: String,
    pub other_key_pem: String,
    /// PRF client identity: CN "minister".
    pub prf_cert_pem: String,
    pub prf_key_pem: String,
}

/// CN of the default client cert.
pub const CLIENT_CN: &str = "freedink";
/// CN of the admin client cert.
pub const ADMIN_CN: &str = "signet-admin";
/// CN of the second, non-allow-listed client cert.
pub const OTHER_CN: &str = "intruder";
/// CN of the PRF client cert.
pub const PRF_CN: &str = "minister";

pub fn make_pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(vec![]).unwrap();
    ca.distinguished_name
        .push(DnType::CommonName, "Signet Test CA");
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

    let mint_client = |cn: &str| {
        let key = KeyPair::generate().unwrap();
        let mut cp = CertificateParams::new(vec![]).unwrap();
        cp.distinguished_name.push(DnType::CommonName, cn);
        cp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = cp.signed_by(&key, &ca_cert, &ca_key).unwrap();
        (cert.pem(), key.serialize_pem())
    };

    let (client_cert_pem, client_key_pem) = mint_client(CLIENT_CN);
    let (admin_cert_pem, admin_key_pem) = mint_client(ADMIN_CN);
    let (other_cert_pem, other_key_pem) = mint_client(OTHER_CN);
    let (prf_cert_pem, prf_key_pem) = mint_client(PRF_CN);

    Pki {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem,
        client_key_pem,
        admin_cert_pem,
        admin_key_pem,
        other_cert_pem,
        other_key_pem,
        prf_cert_pem,
        prf_key_pem,
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

/// PRF-surface knobs for the test server. Present = the surface is enabled
/// through the REAL boot path (seed sealed into service_keys, pairwise
/// imported via the one-shot import path, pin computed and verified).
pub struct PrfOpts {
    /// Identities allowed on the PRF surface (SIGNET_PRF_CLIENT_IDS analogue).
    pub client_ids: BTreeSet<String>,
    /// The FIXED master seed (fixed so frozen vectors are assertable).
    pub master_seed: [u8; 32],
    /// Pairwise secret to import (None = /prf/pairwise not initialized).
    pub pairwise_secret: Option<Vec<u8>>,
    /// Per-identity + global PRF rate-limit ceilings.
    pub rl_identity_max: u32,
    pub rl_global_max: u32,
}

impl Default for PrfOpts {
    fn default() -> Self {
        Self {
            client_ids: id_set(&[PRF_CN]),
            master_seed: *b"MINISTER-TEST-VECTOR-SEED-0001!!",
            pairwise_secret: Some(b"minister-golden-vector-secret-v1-do-not-change!!".to_vec()),
            rl_identity_max: 1_000_000,
            rl_global_max: 1_000_000,
        }
    }
}

/// Configuration knobs for the test server.
pub struct ServerOpts {
    pub rl_participant_max: u32,
    pub rl_global_max: u32,
    pub key_bits: usize,
    /// `/key*` per-identity ceiling.
    pub rl_key_identity_max: u32,
    /// `/key*` global ceiling.
    pub rl_key_global_max: u32,
    /// Concurrent keygen cap.
    pub keygen_max_concurrent: usize,
    /// Allowed client identities (empty = open client list).
    pub allowed_client_ids: BTreeSet<String>,
    /// Admin identities (empty = rotation disabled).
    pub admin_ids: BTreeSet<String>,
    pub auto_create_keys: bool,
    /// PRF surface (None = not mounted, the default — /sign-only tests run
    /// exactly the pre-PRF deployment shape).
    pub prf: Option<PrfOpts>,
}

impl Default for ServerOpts {
    fn default() -> Self {
        // 2048 is required for TS interop, but unit/integration tests that do
        // not check interop can use a smaller modulus to keep keygen fast.
        Self {
            rl_participant_max: 100,
            rl_global_max: 10_000,
            key_bits: 2048,
            // Effectively unlimited by default: many tests poll GET /key in a
            // tight loop while a slow keygen runs, which must not trip the rate
            // limiter. Tests that assert the limiter fires set low caps.
            rl_key_identity_max: 1_000_000,
            rl_key_global_max: 1_000_000,
            keygen_max_concurrent: 2,
            allowed_client_ids: BTreeSet::new(),
            admin_ids: BTreeSet::new(),
            auto_create_keys: true,
            prf: None,
        }
    }
}

/// Convenience: build a set of identity strings.
pub fn id_set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
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
    let db = Arc::new(Db::open(&db_path).unwrap());

    // PRF surface: exercise the REAL lifecycle — seal the fixed seed like
    // init would, then load through the production boot policy (pin check +
    // one-shot pairwise import included).
    let (prf_state, prf_ids) = match &opts.prf {
        Some(prf) => {
            let pin = signet::dedup::seal_master_seed(&db, &kek, &prf.master_seed).unwrap();
            let boot = prepare_prf_boot(
                &db,
                &kek,
                PrfBootArgs {
                    prf_clients_configured: !prf.client_ids.is_empty(),
                    dedup_pubkey_pin: Some(&pin),
                    import_pairwise: prf
                        .pairwise_secret
                        .as_ref()
                        .map(|s| Zeroizing::new(s.clone())),
                },
            )
            .expect("PRF boot policy must enable the surface");
            let keys = match boot {
                PrfBoot::Enabled(keys) => *keys,
                PrfBoot::Disabled => panic!("PRF opts set but boot disabled the surface"),
            };
            (
                Some(PrfState {
                    keys,
                    allowed_client_ids: prf.client_ids.clone(),
                    rate_limiter: KeyRateLimiter::new(prf.rl_identity_max, prf.rl_global_max, 60),
                }),
                prf.client_ids.clone(),
            )
        }
        None => (None, BTreeSet::new()),
    };

    let keygen = KeygenService::new(
        db.clone(),
        kek.clone(),
        opts.key_bits,
        opts.keygen_max_concurrent,
    );
    let state = Arc::new(AppState {
        db,
        kek,
        rate_limiter: RateLimiter::new(opts.rl_participant_max, opts.rl_global_max, 60),
        key_rate_limiter: KeyRateLimiter::new(opts.rl_key_identity_max, opts.rl_key_global_max, 60),
        keygen,
        auto_create_keys: opts.auto_create_keys,
        key_bits: opts.key_bits,
        prf: prf_state,
    });
    let app = signet::router(state);

    let tls = signet::tls::build_server_config(&cert_path, &key_path, &ca_path).unwrap();
    let policy = IdentityPolicy::new(
        opts.allowed_client_ids.clone(),
        opts.admin_ids.clone(),
        prf_ids,
    );

    // Bind an ephemeral port via std, learn the addr, then hand to the shared
    // identity-pinning serve path.
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        signet::serve(listener, tls, policy, app).await.unwrap();
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

/// Build a reqwest client presenting the given cert+key PEM as its identity.
fn client_with_identity(pki: &Pki, cert_pem: &str, key_pem: &str) -> reqwest::Client {
    let mut identity_pem = cert_pem.to_string();
    identity_pem.push_str(key_pem);
    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap();
    let ca = reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap();
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca)
        .identity(identity)
        .build()
        .unwrap()
}

/// A reqwest client that presents the default client certificate (CN freedink).
pub fn client_with_cert(pki: &Pki) -> reqwest::Client {
    client_with_identity(pki, &pki.client_cert_pem, &pki.client_key_pem)
}

/// A reqwest client presenting the admin certificate (CN signet-admin).
pub fn admin_client(pki: &Pki) -> reqwest::Client {
    client_with_identity(pki, &pki.admin_cert_pem, &pki.admin_key_pem)
}

/// A reqwest client presenting the second non-admin cert (CN intruder); chains
/// to the CA but is not on a configured allow-list.
pub fn other_client(pki: &Pki) -> reqwest::Client {
    client_with_identity(pki, &pki.other_cert_pem, &pki.other_key_pem)
}

/// A reqwest client presenting the PRF client certificate (CN minister).
pub fn prf_client(pki: &Pki) -> reqwest::Client {
    client_with_identity(pki, &pki.prf_cert_pem, &pki.prf_key_pem)
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
