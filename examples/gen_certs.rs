//! Dev mTLS certificate generator (pure Rust, no openssl needed).
//!
//! Produces a self-signed CA and two leaf certs into an output directory:
//!   ca.pem / ca.key            - the CA (signs both leaves; trusted by both ends)
//!   server.pem / server.key    - Signet's server cert (SAN below; ServerAuth)
//!   client.pem / client.key    - FreedInk's client cert (ClientAuth)
//!
//! Usage:
//!   cargo run --release --example gen_certs -- <out_dir> [server_san ...]
//!
//! Defaults the server SANs to: signet, localhost, 127.0.0.1. In docker-compose
//! the server is reachable as `signet` on the internal network, so that SAN
//! must be present for FreedInk's TLS hostname check.
//!
//! THESE ARE DEV CERTS. For production, mint client certs from your real PKI and
//! keep the CA key offline.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    let out_dir = args.next().unwrap_or_else(|| "deploy/certs".to_string());
    let extra_sans: Vec<String> = args.collect();
    let out = Path::new(&out_dir);
    fs::create_dir_all(out).expect("create out dir");

    // --- CA ---
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(vec![]).expect("ca params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Signet Dev CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

    write(out, "ca.pem", &ca_cert.pem());
    write(out, "ca.key", &ca_key.serialize_pem());

    // --- Server cert (Signet) ---
    let mut sans: Vec<SanType> = vec![
        SanType::DnsName("signet".try_into().unwrap()),
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::IpAddress(Ipv4Addr::new(127, 0, 0, 1).into()),
    ];
    for s in &extra_sans {
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            sans.push(SanType::IpAddress(ip));
        } else {
            sans.push(SanType::DnsName(s.clone().try_into().expect("invalid SAN")));
        }
    }
    let server_key = KeyPair::generate().expect("server key");
    let mut server_params = CertificateParams::new(vec![]).expect("server params");
    server_params
        .distinguished_name
        .push(DnType::CommonName, "signet");
    server_params.subject_alt_names = sans;
    server_params.is_ca = IsCa::NoCa;
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("sign server");
    write(out, "server.pem", &server_cert.pem());
    write(out, "server.key", &server_key.serialize_pem());

    // --- Client cert (FreedInk) ---
    let client_key = KeyPair::generate().expect("client key");
    let mut client_params = CertificateParams::new(vec![]).expect("client params");
    client_params
        .distinguished_name
        .push(DnType::CommonName, "freedink");
    client_params.is_ca = IsCa::NoCa;
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("sign client");
    write(out, "client.pem", &client_cert.pem());
    write(out, "client.key", &client_key.serialize_pem());

    eprintln!("wrote CA + server + client certs to {}", out.display());
    eprintln!("server SANs: signet, localhost, 127.0.0.1{}",
        if extra_sans.is_empty() { String::new() } else { format!(", {}", extra_sans.join(", ")) });
}

fn write(dir: &Path, name: &str, contents: &str) {
    let path = dir.join(name);
    fs::write(&path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}
