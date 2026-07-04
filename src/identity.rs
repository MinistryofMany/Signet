//! Client-identity pinning on top of mTLS (audit M1 + M3).
//!
//! mTLS alone only proves a client certificate chains to `SIGNET_CLIENT_CA`.
//! That is not sufficient access control: *any* certificate issued under that
//! CA could otherwise call every endpoint, including key creation and rotation.
//! This module pins the peer's identity (the leaf certificate's Common Name or
//! a DNS Subject Alternative Name) and classifies it into a role:
//!
//!   - **client**  — may call `/sign`, `/key` (GET/POST). The allow-list is
//!     `SIGNET_ALLOWED_CLIENT_IDS`; if that is empty, any valid-chain cert is
//!     accepted (back-compat) and a warning is logged at startup.
//!   - **admin**   — additionally may call `/key/rotate`. The allow-list is
//!     `SIGNET_ADMIN_IDS`; if it is empty, `/key/rotate` is refused for
//!     everyone (fail-closed: no admin identity configured => no rotation).
//!   - **prf**     — admitted SOLELY via `SIGNET_PRF_CLIENT_IDS` (not on the
//!     client/admin lists). May call only the `/prf/*` and `/dedup/*`
//!     endpoints; the blind-RSA surface (`/sign`, `/key*`) refuses it, so
//!     admitting Minister for PRF work never widens the /sign surface.
//!
//! PRF authorization is deliberately NOT granted by `classify`'s client rules:
//! the open back-compat client list ("empty = any valid-chain cert") must
//! never reach the PRF surface, which includes a raw HMAC oracle over the
//! pairwise secret. Instead every identity carries a `prf_allowed` flag,
//! matched ONLY against the dedicated `SIGNET_PRF_CLIENT_IDS` set, and every
//! `/prf/*` / `/dedup/*` handler checks it per-route (mirroring the
//! `is_admin()` gate on `/key/rotate`), where the pinned identity NAME is
//! additionally re-checked against the same set — fail-closed at both layers.
//!
//! CA ISSUANCE DISCIPLINE (load-bearing for the PRF allow-list): the
//! candidate names cover the leaf CN plus EVERY DNS SAN, so a certificate
//! signed from a CSR-supplied name set could smuggle a PRF identity (e.g. a
//! dNSName "minister") onto an RP certificate and silently grant it the full
//! PRF surface, including the pairwise HMAC oracle. The Signet client CA
//! must therefore issue client certificates with operator-fixed CN/SAN only
//! — never sign CSR-supplied subject names or SANs verbatim — and PRF
//! identities should use names no RP certificate would legitimately carry
//! (a dedicated prefix such as `prf-` makes a collision visually
//! impossible). The in-handler name re-check narrows the blast radius of a
//! sloppy issuance (the pinned name must itself be PRF-listed) but does not
//! remove it: a cert whose FIRST candidate is the smuggled name still pins
//! it. Issuance discipline is the actual boundary.
//!
//! Enforcement happens in two places:
//!   1. **Connection admission** (`IdentityAcceptor`): when an allow-list is
//!      configured, a peer whose identity is on none of the client, admin, or
//!      PRF lists is dropped at the TLS layer, before any HTTP runs.
//!   2. **Per-route gating** (the [`ClientIdentity`] extractor + role check in
//!      the handlers): `/key/rotate` requires the `Admin` role even for an
//!      otherwise-allowed client; `/prf/*` and `/dedup/*` require
//!      `prf_allowed`; `/sign` and `/key*` refuse `Prf`-role identities.
//!
//! How the cert reaches a handler: axum-server's standard serve path consumes
//! the rustls connection into the hyper IO and never surfaces the peer
//! certificate to the service. So we install a custom [`Accept`] implementation
//! that performs the TLS handshake itself, reads the verified peer leaf from the
//! `ServerConnection`, parses the identity, and wraps the per-connection service
//! so every request carries a [`ClientIdentity`] in its extensions.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_server::accept::Accept;
use rustls::ServerConfig;
use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tower::Service;

/// The role a pinned client identity is authorized for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Allowed to sign and read/create keys, but not to rotate.
    Client,
    /// Allowed to do everything a client can, plus rotate keys.
    Admin,
    /// Admitted SOLELY via the PRF allow-list: may call only the `/prf/*` and
    /// `/dedup/*` endpoints. The blind-RSA surface refuses this role, so a
    /// PRF-only identity (Minister) never gains /sign access as a side
    /// effect of being admitted.
    Prf,
}

/// A verified peer identity, derived from the mTLS leaf certificate.
///
/// `name` is the identity that matched the allow-list (a CN or a DNS SAN), used
/// for audit logging and as the per-identity rate-limit key. `role` is the
/// authorization tier the identity was classified into. `prf_allowed` is
/// matched ONLY against `SIGNET_PRF_CLIENT_IDS` — never implied by the client
/// list or its open back-compat mode.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    pub name: String,
    pub role: Role,
    pub prf_allowed: bool,
}

impl ClientIdentity {
    /// True if this identity is permitted to rotate keys.
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }

    /// True if this identity may call the blind-RSA surface (/sign, /key*).
    pub fn may_sign(&self) -> bool {
        matches!(self.role, Role::Client | Role::Admin)
    }

    /// True if this identity may call the PRF surface (/prf/*, /dedup/*).
    pub fn may_prf(&self) -> bool {
        self.prf_allowed
    }
}

/// The configured allow-lists that classify a peer identity into a role.
///
/// Identities are matched case-sensitively against the certificate's CN and any
/// DNS SAN. An identity on the admin list outranks the client list.
#[derive(Debug, Clone)]
pub struct IdentityPolicy {
    allowed_clients: Arc<BTreeSet<String>>,
    admins: Arc<BTreeSet<String>>,
    prf_clients: Arc<BTreeSet<String>>,
}

impl IdentityPolicy {
    pub fn new(
        allowed_clients: BTreeSet<String>,
        admins: BTreeSet<String>,
        prf_clients: BTreeSet<String>,
    ) -> Self {
        Self {
            allowed_clients: Arc::new(allowed_clients),
            admins: Arc::new(admins),
            prf_clients: Arc::new(prf_clients),
        }
    }

    /// True if no client allow-list is configured (any valid-chain cert is then
    /// accepted as a client). Used to emit a startup warning.
    pub fn client_list_is_open(&self) -> bool {
        self.allowed_clients.is_empty()
    }

    /// True if no admin identity is configured (rotation is then disabled).
    pub fn admin_list_is_empty(&self) -> bool {
        self.admins.is_empty()
    }

    /// Classify a set of candidate identity names (the leaf's CN plus its DNS
    /// SANs) into a role, or `None` if the peer is not permitted at all.
    ///
    /// Admin is checked first so an identity on both lists is treated as admin.
    /// If the client allow-list is empty, every peer is at least a `Client`
    /// (back-compat); the admin list is always enforced explicitly. The PRF
    /// list admits otherwise-unlisted identities with the restricted `Prf`
    /// role, and sets `prf_allowed` on any admitted identity whose candidates
    /// match it — the ONLY way `prf_allowed` becomes true.
    pub fn classify(&self, candidates: &[String]) -> Option<ClientIdentity> {
        let prf_allowed = candidates.iter().any(|c| self.prf_clients.contains(c));
        let admin_match = candidates.iter().find(|c| self.admins.contains(*c));
        if let Some(name) = admin_match {
            return Some(ClientIdentity {
                name: name.clone(),
                role: Role::Admin,
                prf_allowed,
            });
        }
        if self.allowed_clients.is_empty() {
            // Open client list: accept any valid-chain cert as a client. Prefer
            // a stable, human-meaningful name for audit/rate-limit keying.
            let name = candidates
                .first()
                .cloned()
                .unwrap_or_else(|| "<unnamed-client>".to_string());
            return Some(ClientIdentity {
                name,
                role: Role::Client,
                prf_allowed,
            });
        }
        if let Some(name) = candidates
            .iter()
            .find(|c| self.allowed_clients.contains(*c))
        {
            return Some(ClientIdentity {
                name: name.clone(),
                role: Role::Client,
                prf_allowed,
            });
        }
        // Not on the client list: admit with the restricted Prf role iff on
        // the PRF list (per-route gates take it from here).
        if prf_allowed {
            let name = candidates
                .iter()
                .find(|c| self.prf_clients.contains(*c))
                .cloned()
                .unwrap_or_else(|| "<unnamed-prf-client>".to_string());
            return Some(ClientIdentity {
                name,
                role: Role::Prf,
                prf_allowed,
            });
        }
        None
    }
}

/// Extract the candidate identity names (CN + DNS SANs) from a leaf cert DER.
///
/// Returns an empty vec if the certificate cannot be parsed; the caller then
/// treats the peer as unidentified. The chain itself was already validated by
/// rustls' `WebPkiClientVerifier` before we ever see this leaf.
pub fn identity_names_from_leaf(leaf_der: &[u8]) -> Vec<String> {
    use x509_parser::prelude::*;

    let mut names = Vec::new();
    let parsed = match X509Certificate::from_der(leaf_der) {
        Ok((_, c)) => c,
        Err(_) => return names,
    };
    for cn in parsed.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            names.push(s.to_string());
        }
    }
    if let Ok(Some(san)) = parsed.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::DNSName(dns) = gn {
                names.push((*dns).to_string());
            }
        }
    }
    names
}

// ---------------------------------------------------------------------------
// Custom Accept: run the TLS handshake, pin identity, inject it per request.
// ---------------------------------------------------------------------------

/// An [`Accept`] implementation that terminates TLS, pins the peer identity
/// against [`IdentityPolicy`], and wraps the per-connection service so every
/// request carries the resolved [`ClientIdentity`] in its extensions.
/// Default TLS handshake timeout. A peer that opens a connection but stalls the
/// handshake (slow-loris) is dropped after this, so half-open accept futures
/// cannot accumulate. Generous relative to a real handshake (sub-second on the
/// internal network) while still bounded.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct IdentityAcceptor {
    config: Arc<ServerConfig>,
    policy: IdentityPolicy,
    handshake_timeout: Duration,
}

impl IdentityAcceptor {
    pub fn new(config: Arc<ServerConfig>, policy: IdentityPolicy) -> Self {
        Self {
            config,
            policy,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Override the TLS handshake timeout (tuning / tests).
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }
}

impl<I, S> Accept<I, S> for IdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = IdentityService<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let config = self.config.clone();
        let policy = self.policy.clone();
        let handshake_timeout = self.handshake_timeout;
        Box::pin(async move {
            let acceptor = TlsAcceptor::from(config);
            // Bound the handshake: a peer that connects but never completes the
            // TLS handshake (slow-loris) must not pin an accept future open
            // indefinitely. On timeout we drop the connection with a TimedOut
            // error rather than awaiting the peer forever.
            let tls = match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
                Ok(result) => result?,
                Err(_elapsed) => {
                    tracing::warn!(
                        timeout_ms = handshake_timeout.as_millis() as u64,
                        "dropping connection: TLS handshake exceeded the timeout"
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TLS handshake timed out",
                    ));
                }
            };

            // The chain was already verified by WebPkiClientVerifier; here we
            // only read the leaf to derive identity. mTLS is mandatory, so a
            // missing peer cert is an internal invariant violation -> reject.
            let identity = {
                let (_io, conn) = tls.get_ref();
                let leaf = conn
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "mTLS: no peer certificate present after handshake",
                        )
                    })?;
                let candidates = identity_names_from_leaf(leaf.as_ref());
                match policy.classify(&candidates) {
                    Some(id) => id,
                    None => {
                        tracing::warn!(
                            candidates = ?candidates,
                            "rejecting connection: client identity not on any allow-list"
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "client identity not permitted",
                        ));
                    }
                }
            };

            Ok((tls, IdentityService::new(service, identity)))
        })
    }
}

/// A [`Service`] wrapper that inserts a fixed [`ClientIdentity`] into every
/// request's extensions before delegating to the inner service. One instance
/// exists per accepted connection, so the identity is constant for its lifetime.
#[derive(Clone)]
pub struct IdentityService<S> {
    inner: S,
    identity: ClientIdentity,
}

impl<S> IdentityService<S> {
    fn new(inner: S, identity: ClientIdentity) -> Self {
        Self { inner, identity }
    }
}

impl<S, B> Service<axum::http::Request<B>> for IdentityService<S>
where
    S: Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
        req.extensions_mut().insert(self.identity.clone());
        self.inner.call(req)
    }
}

// ---------------------------------------------------------------------------
// Extractor: pull the pinned identity out of request extensions in a handler.
// ---------------------------------------------------------------------------

impl<St> FromRequestParts<St> for ClientIdentity
where
    St: Send + Sync,
{
    type Rejection = crate::error::AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &St) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ClientIdentity>()
            .cloned()
            .ok_or_else(|| {
                // The identity is injected by IdentityService for every mTLS
                // connection. Its absence means the service was wired without
                // the identity acceptor -> refuse rather than fail open.
                tracing::error!("client identity missing from request extensions");
                crate::error::AppError::Internal("client identity unavailable".into())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(clients: &[&str], admins: &[&str]) -> IdentityPolicy {
        policy_with_prf(clients, admins, &[])
    }

    fn policy_with_prf(clients: &[&str], admins: &[&str], prf: &[&str]) -> IdentityPolicy {
        IdentityPolicy::new(
            clients.iter().map(|s| s.to_string()).collect(),
            admins.iter().map(|s| s.to_string()).collect(),
            prf.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn empty_client_list_accepts_any_as_client() {
        let p = policy(&[], &[]);
        let id = p
            .classify(&["whoever".to_string()])
            .expect("open list admits");
        assert_eq!(id.role, Role::Client);
        assert_eq!(id.name, "whoever");
    }

    #[test]
    fn unknown_identity_rejected_when_list_set() {
        let p = policy(&["freedink"], &[]);
        assert!(p.classify(&["intruder".to_string()]).is_none());
        let id = p.classify(&["freedink".to_string()]).unwrap();
        assert_eq!(id.role, Role::Client);
    }

    #[test]
    fn admin_outranks_client_and_is_matched_first() {
        let p = policy(&["freedink"], &["signet-admin"]);
        let id = p
            .classify(&["signet-admin".to_string()])
            .expect("admin admitted");
        assert_eq!(id.role, Role::Admin);
        assert!(id.is_admin());
        // A client identity is admitted but only as Client.
        let c = p.classify(&["freedink".to_string()]).unwrap();
        assert_eq!(c.role, Role::Client);
        assert!(!c.is_admin());
    }

    #[test]
    fn dns_san_matches_allow_list() {
        let p = policy(&["client.signet.internal"], &[]);
        // CN is unknown but a DNS SAN matches.
        let id = p
            .classify(&["some-cn".to_string(), "client.signet.internal".to_string()])
            .expect("SAN match admits");
        assert_eq!(id.name, "client.signet.internal");
        assert_eq!(id.role, Role::Client);
    }

    #[test]
    fn admin_list_empty_means_no_admin_role() {
        let p = policy(&["freedink"], &[]);
        assert!(p.admin_list_is_empty());
        // Even the configured client cannot reach admin.
        let id = p.classify(&["freedink".to_string()]).unwrap();
        assert!(!id.is_admin());
    }

    #[test]
    fn prf_allowed_comes_only_from_the_prf_list() {
        // The open back-compat client list must NEVER grant PRF access.
        let p = policy_with_prf(&[], &[], &["minister"]);
        let open = p.classify(&["whoever".to_string()]).unwrap();
        assert_eq!(open.role, Role::Client);
        assert!(!open.may_prf(), "open client list must not grant PRF");
        // A configured client off the PRF list gets no PRF either.
        let p = policy_with_prf(&["freedink"], &[], &["minister"]);
        let c = p.classify(&["freedink".to_string()]).unwrap();
        assert!(c.may_sign());
        assert!(!c.may_prf());
        // The PRF-listed identity is PRF-allowed.
        let m = p.classify(&["minister".to_string()]).unwrap();
        assert!(m.may_prf());
    }

    #[test]
    fn prf_only_identity_gets_restricted_role() {
        // With a configured client list, a PRF-only identity is admitted with
        // the Prf role: it may reach /prf but NOT the blind-RSA surface.
        let p = policy_with_prf(&["freedink"], &[], &["minister"]);
        let m = p.classify(&["minister".to_string()]).unwrap();
        assert_eq!(m.role, Role::Prf);
        assert_eq!(m.name, "minister");
        assert!(m.may_prf());
        assert!(!m.may_sign());
        assert!(!m.is_admin());
        // An identity on BOTH lists keeps full client access plus PRF.
        let p = policy_with_prf(&["freedink", "minister"], &[], &["minister"]);
        let m = p.classify(&["minister".to_string()]).unwrap();
        assert_eq!(m.role, Role::Client);
        assert!(m.may_prf());
        assert!(m.may_sign());
    }

    #[test]
    fn unlisted_identity_still_rejected_with_prf_list_configured() {
        let p = policy_with_prf(&["freedink"], &[], &["minister"]);
        assert!(p.classify(&["intruder".to_string()]).is_none());
    }

    #[tokio::test]
    async fn tls_handshake_past_the_timeout_is_dropped() {
        use axum_server::accept::Accept;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::ServerConfig;
        use std::collections::BTreeSet;
        use std::pin::Pin;
        use std::sync::Arc;
        use std::task::{Context as TaskContext, Poll};
        use std::time::Duration;
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        // A stream that accepts writes but never yields read data, so the TLS
        // server side blocks forever waiting for the ClientHello (slow-loris).
        struct StalledStream;
        impl AsyncRead for StalledStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut TaskContext<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for StalledStream {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut TaskContext<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut TaskContext<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // Install the process crypto provider (idempotent across tests).
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Minimal self-signed server config; the handshake never gets far enough
        // to validate it (the timeout fires first), so no CA / client auth needed.
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

        let acceptor = IdentityAcceptor::new(
            Arc::new(config),
            IdentityPolicy::new(BTreeSet::new(), BTreeSet::new(), BTreeSet::new()),
        )
        .with_handshake_timeout(Duration::from_millis(100));

        // Outer guard: a regression (no handshake timeout) would hang here and
        // fail the test deterministically instead of blocking forever.
        let outcome =
            tokio::time::timeout(Duration::from_secs(3), acceptor.accept(StalledStream, ()))
                .await
                .expect("accept() did not return within 3s - handshake timeout missing?");

        // Avoid `expect_err`, which would require the Ok variant to be `Debug`.
        match outcome {
            Ok(_) => panic!("a stalled handshake must be rejected, not admitted"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::TimedOut),
        }
    }
}
