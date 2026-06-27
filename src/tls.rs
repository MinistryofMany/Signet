//! Mutual-TLS server configuration.
//!
//! The server presents its own certificate AND requires a client certificate
//! chaining to the configured CA. A client with no certificate, or a cert not
//! signed by the trusted CA, is rejected at the TLS layer before any HTTP is
//! processed. This is the primary access control: only holders of a valid
//! client cert (i.e. FreedInk) can reach `/sign`.

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Build a rustls `ServerConfig` that:
///  - presents `server_cert_pem` / `server_key_pem`, and
///  - requires (mandatory) a client cert chaining to `client_ca_pem`.
pub fn build_server_config(
    server_cert_pem: &Path,
    server_key_pem: &Path,
    client_ca_pem: &Path,
) -> Result<Arc<ServerConfig>, String> {
    let certs = load_certs(server_cert_pem)?;
    let key = load_private_key(server_key_pem)?;
    let client_roots = load_root_store(client_ca_pem)?;

    // Mandatory client auth: builder().build() refuses connections without a
    // trusted client certificate. (allow_unauthenticated() would make it
    // optional; we deliberately do NOT call it.)
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(|e| format!("client verifier build failed: {e}"))?;

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("server config build failed: {e}"))?;

    // axum-server's from_config requires us to set ALPN explicitly.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parse certs {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("no certificates in {}", path.display()));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let data = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("parse key {}: {e}", path.display()))?
        .ok_or_else(|| format!("no private key in {}", path.display()))
}

fn load_root_store(path: &Path) -> Result<RootCertStore, String> {
    let certs = load_certs(path)?;
    let mut store = RootCertStore::empty();
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| format!("add CA cert from {}: {e}", path.display()))?;
    }
    Ok(store)
}
