//! PRF core for the Minister nullifier + pairwise surface.
//!
//! Three primitives, all keyed from material sealed in `service_keys`:
//!
//! 1. **Stage-1 dedup VOPRF** — RFC 9497, VOPRF mode (0x01), ciphersuite
//!    ristretto255-SHA512 (`voprf` crate, curve25519-dalek backend). Minister
//!    blinds the credential anchor; Signet evaluates BLIND (it never sees the
//!    anchor) and returns the evaluation element plus a DLEQ proof that the
//!    evaluation used the pinned key; Minister finalizes to the deterministic
//!    64-byte `N_dedup`, which it registers in the dedup ledger.
//! 2. **Stage-2 disclose HMAC** — computed INSIDE Signet over the STORED
//!    `N_dedup`: `N_rp = "mnv1:" || base64url(HMAC-SHA256(k_disc(clientId),
//!    LP("minister/null/v1") || LP("rp") || LP(N_dedup) || LP(clientId)))`.
//!    Per-RP distinct keys; the clientId appears in BOTH the key derivation
//!    and the message (belt and braces against a derivation bug collapsing
//!    RPs). Deliberately not blinded and not proof-carrying: the input is a
//!    PRF output Signet already stores, and Minister could not DLEQ-verify it
//!    without holding `N_dedup` (which would recreate the equality oracle the
//!    ledger was moved here to avoid).
//! 3. **Pairwise HMAC oracle** — keyed HMAC-SHA256 over an opaque input with
//!    the IMPORTED live `OIDC_PAIRWISE_SECRET` bytes, preserving byte-for-byte
//!    output stability with Minister's live Node path (which is what makes the
//!    pairwise cutover provable and its local fallback safe).
//!
//! Key schedule (two roots, never rotated):
//!
//! ```text
//! master_seed (32B OS RNG, explicit one-shot init only)
//!   ├─ seed_null = HKDF-SHA512(ikm=master_seed, salt="", info="minister/v1/nullifier", L=32)
//!   │    └─ (skS, pkS) = DeriveKeyPair(seed_null, info="minister/v1/nullifier/dedup")  [RFC 9497 §3.2.1]
//!   └─ k_disc(clientId) = HKDF-SHA512(ikm=master_seed, salt="",
//!                                     info="minister/v1/nullifier/disclose" || LP(clientId), L=32)
//! pairwise secret (imported once, sealed; exact UTF-8 bytes of the live secret)
//! ```
//!
//! Input encoding: `LP(x)` = 2-byte big-endian byte length of x followed by
//! the bytes — NEVER bare concatenation (a variable-length attacker-influenced
//! field could otherwise collide two distinct tuples into one PRF input).
//! Handlers cap every field (anchor <= 512 is enforced Minister-side before
//! blinding; badge_type <= 64, clientId <= 256 here), so lengths always fit.
//!
//! Wire encoding note: every binary field on the PRF/dedup HTTP surface uses
//! base64url WITHOUT padding (matching the base64url outputs Minister's
//! pairwise path produces). The blind-RSA surface keeps standard base64.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use voprf::{BlindedElement, Group, Ristretto255, VoprfServer};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// `service_keys.purpose` of the sealed 32-byte nullifier master seed.
pub const MASTER_SEED_PURPOSE: &str = "master-seed-v1";
/// `service_keys.purpose` of the sealed imported pairwise HMAC secret.
pub const PAIRWISE_HMAC_PURPOSE: &str = "pairwise-hmac-v1";
/// Master seed length (bytes).
pub const MASTER_SEED_LEN: usize = 32;
/// The VOPRF ciphersuite identifier served on /prf/public-key.
pub const SUITE: &str = "ristretto255-SHA512";
/// Serialized ristretto255 group element length (blinded element, evaluation
/// element, public key).
pub const ELEMENT_LEN: usize = 32;
/// Serialized DLEQ proof length (two 32-byte scalars, c || s).
pub const PROOF_LEN: usize = 64;
/// Stage-1 output (`N_dedup`) length: the SHA-512 Finalize output.
pub const DEDUP_VALUE_LEN: usize = 64;
/// Version prefix stamped on every disclosed nullifier, forever.
pub const NULLIFIER_PREFIX: &str = "mnv1:";

const INFO_NULLIFIER_SEED: &[u8] = b"minister/v1/nullifier";
const INFO_DEDUP_KEYPAIR: &[u8] = b"minister/v1/nullifier/dedup";
const INFO_DISCLOSE: &[u8] = b"minister/v1/nullifier/disclose";
const TAG_PROTOCOL: &str = "minister/null/v1";
const TAG_DEDUP: &str = "dedup";
const TAG_RP: &str = "rp";

/// Append `LP(bytes)`: 2-byte big-endian length, then the bytes.
///
/// Panics if `bytes` exceeds `u16::MAX` — callers cap every field orders of
/// magnitude below that, so a panic here is an internal invariant violation,
/// not a reachable input path.
fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("LP input exceeds u16::MAX; caller must cap");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The stage-1 dedup PRF input for a credential anchor:
/// `LP("minister/null/v1") || LP("dedup") || LP(sybil_id) || LP(badge_type)`.
///
/// Production Signet NEVER computes this — Minister builds it, blinds it, and
/// sends only the blinded element. It lives here as the single frozen
/// definition shared by the golden-vector tests and the cross-language
/// interop harness.
pub fn dedup_input(sybil_id: &str, badge_type: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        8 + TAG_PROTOCOL.len() + TAG_DEDUP.len() + sybil_id.len() + badge_type.len(),
    );
    lp(&mut out, TAG_PROTOCOL.as_bytes());
    lp(&mut out, TAG_DEDUP.as_bytes());
    lp(&mut out, sybil_id.as_bytes());
    lp(&mut out, badge_type.as_bytes());
    out
}

/// Errors surfaced to handlers. Deliberately carries no detail: a bad group
/// element is a 400, never a 500, and never echoes input bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum PrfError {
    /// The supplied bytes are not a valid ristretto255 group element.
    BadElement,
}

/// Result of a blind evaluation: both fields serialized, ready for the wire.
/// (Both are public wire values; Debug is derived for test ergonomics.)
#[derive(Debug)]
pub struct EvaluateOutput {
    /// Serialized evaluation element (32 bytes).
    pub evaluation_element: Vec<u8>,
    /// Serialized DLEQ proof (64 bytes, c || s).
    pub proof: Vec<u8>,
}

/// The in-memory PRF key material for an enabled PRF surface.
///
/// Holds the VOPRF secret scalar, the master seed (for per-RP disclose-key
/// derivation), and the imported pairwise secret — the operating keys of the
/// service, same sensitivity class as the process-held KEK. The seed and
/// pairwise secret are zeroized on drop.
pub struct PrfKeys {
    server: VoprfServer<Ristretto255>,
    master_seed: Zeroizing<[u8; MASTER_SEED_LEN]>,
    pairwise: Option<Zeroizing<Vec<u8>>>,
}

impl PrfKeys {
    /// Derive the full key schedule from the master seed (and optionally the
    /// imported pairwise secret). Deterministic: the same seed always yields
    /// the same `(skS, pkS)` — the property the boot-time public-key pin
    /// check relies on.
    pub fn from_seed(
        master_seed: [u8; MASTER_SEED_LEN],
        pairwise: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Self, String> {
        let master_seed = Zeroizing::new(master_seed);
        let hk = Hkdf::<Sha512>::new(None, master_seed.as_ref());
        let mut seed_null = Zeroizing::new([0u8; 32]);
        hk.expand(INFO_NULLIFIER_SEED, seed_null.as_mut())
            .map_err(|_| "HKDF expand for the nullifier seed failed".to_string())?;
        let server =
            VoprfServer::<Ristretto255>::new_from_seed(seed_null.as_ref(), INFO_DEDUP_KEYPAIR)
                .map_err(|e| format!("VOPRF DeriveKeyPair failed: {e:?}"))?;
        Ok(Self {
            server,
            master_seed,
            pairwise,
        })
    }

    /// The serialized VOPRF public key `pkS` (32 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        <Ristretto255 as Group>::serialize_elem(self.server.get_public_key()).to_vec()
    }

    /// `pkS` in the pin encoding (base64url, no padding) — the exact string
    /// `init-service-keys` prints and `SIGNET_DEDUP_PUBKEY_PIN` must equal.
    pub fn public_key_b64(&self) -> String {
        B64URL.encode(self.public_key_bytes())
    }

    /// Blind-evaluate a serialized blinded element, returning the evaluation
    /// element and a DLEQ proof against `pkS`. The element is validated by
    /// deserialization (a non-canonical or identity encoding is rejected).
    pub fn evaluate(&self, blinded_element: &[u8]) -> Result<EvaluateOutput, PrfError> {
        let element = BlindedElement::<Ristretto255>::deserialize(blinded_element)
            .map_err(|_| PrfError::BadElement)?;
        let result = self.server.blind_evaluate(&mut rand_core::OsRng, &element);
        Ok(EvaluateOutput {
            evaluation_element: result.message.serialize().to_vec(),
            proof: result.proof.serialize().to_vec(),
        })
    }

    /// Full unblinded VOPRF evaluation. Tests and fixture generation ONLY:
    /// the HTTP surface never accepts an unblinded input (production anchors
    /// reach Signet only as blinded elements). Not routed.
    pub fn evaluate_unblinded(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        self.server
            .evaluate(input)
            .map(|o| o.to_vec())
            .map_err(|e| format!("VOPRF evaluate failed: {e:?}"))
    }

    /// Stage-2 per-RP disclosure over the STORED `N_dedup`.
    pub fn disclose(&self, n_dedup: &[u8], client_id: &str) -> String {
        // k_disc(clientId) = HKDF-SHA512(master_seed, "", INFO_DISCLOSE || LP(clientId), 32)
        let mut info = Vec::with_capacity(INFO_DISCLOSE.len() + 2 + client_id.len());
        info.extend_from_slice(INFO_DISCLOSE);
        lp(&mut info, client_id.as_bytes());
        let hk = Hkdf::<Sha512>::new(None, self.master_seed.as_ref());
        let mut k_disc = Zeroizing::new([0u8; 32]);
        hk.expand(&info, k_disc.as_mut())
            .expect("32 bytes is a valid HKDF-SHA512 output length");

        let mut msg = Vec::with_capacity(
            8 + TAG_PROTOCOL.len() + TAG_RP.len() + n_dedup.len() + client_id.len(),
        );
        lp(&mut msg, TAG_PROTOCOL.as_bytes());
        lp(&mut msg, TAG_RP.as_bytes());
        lp(&mut msg, n_dedup);
        lp(&mut msg, client_id.as_bytes());

        let mut mac =
            HmacSha256::new_from_slice(k_disc.as_ref()).expect("HMAC accepts any key length");
        mac.update(&msg);
        format!(
            "{NULLIFIER_PREFIX}{}",
            B64URL.encode(mac.finalize().into_bytes())
        )
    }

    /// Whether the pairwise secret has been imported.
    pub fn has_pairwise(&self) -> bool {
        self.pairwise.is_some()
    }

    /// The pairwise HMAC oracle: `base64url(HMAC-SHA256(secret, input))`, no
    /// padding — byte-identical to Minister's live Node derivation. Returns
    /// `None` when no pairwise secret has been imported (the caller maps that
    /// to a fail-closed 404).
    pub fn pairwise(&self, input: &[u8]) -> Option<String> {
        let key = self.pairwise.as_ref()?;
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(input);
        Some(B64URL.encode(mac.finalize().into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voprf::VoprfClient;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn lp_is_two_byte_big_endian_length_prefixed() {
        let mut out = Vec::new();
        lp(&mut out, b"");
        lp(&mut out, b"ab");
        assert_eq!(out, [0x00, 0x00, 0x00, 0x02, b'a', b'b']);
        let mut long = Vec::new();
        lp(&mut long, &[0x7f; 300]);
        assert_eq!(&long[..2], &[0x01, 0x2c], "300 as 2-byte big-endian");
        assert_eq!(long.len(), 302);
    }

    #[test]
    fn dedup_input_is_lp_framed_and_collision_free_across_field_splits() {
        let a = dedup_input("ab", "c");
        let b = dedup_input("a", "bc");
        assert_ne!(a, b, "LP framing must separate (ab,c) from (a,bc)");
        let expected = {
            let mut v = Vec::new();
            lp(&mut v, b"minister/null/v1");
            lp(&mut v, b"dedup");
            lp(&mut v, b"ab");
            lp(&mut v, b"c");
            v
        };
        assert_eq!(a, expected);
    }

    // -----------------------------------------------------------------------
    // RFC 9497 Appendix A.1.2 — VOPRF mode, ristretto255-SHA512.
    // The decision gate for the ciphersuite: these vectors passing (together
    // with the cross-language interop harness) is what keeps ristretto255;
    // a failure here means falling back to P256-SHA256 per the build plan.
    // -----------------------------------------------------------------------

    const RFC_SEED: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
    const RFC_KEY_INFO: &[u8] = b"test key";
    const RFC_PKSM: &str = "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e";

    fn rfc_server() -> VoprfServer<Ristretto255> {
        VoprfServer::<Ristretto255>::new_from_seed(&unhex(RFC_SEED), RFC_KEY_INFO).unwrap()
    }

    #[test]
    fn rfc9497_derive_key_pair_matches_pksm() {
        let server = rfc_server();
        let pk = <Ristretto255 as Group>::serialize_elem(server.get_public_key());
        assert_eq!(hex::encode(pk), RFC_PKSM);
    }

    struct RfcVector {
        input: &'static str,
        blind: &'static str,
        blinded_element: &'static str,
        evaluation_element: &'static str,
        output: &'static str,
    }

    const RFC_VECTORS: [RfcVector; 2] = [
        RfcVector {
            input: "00",
            blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
            blinded_element: "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945",
            evaluation_element: "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e",
            output: "b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c",
        },
        RfcVector {
            input: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            blind: "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
            blinded_element: "cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c",
            evaluation_element: "60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468",
            output: "8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6",
        },
    ];

    #[test]
    fn rfc9497_vectors_roundtrip_byte_exact() {
        let server = rfc_server();
        let pk = server.get_public_key();
        for v in &RFC_VECTORS {
            let input = unhex(v.input);
            let blind = <Ristretto255 as Group>::deserialize_scalar(&unhex(v.blind)).unwrap();
            // Deterministic blind (danger feature) to reproduce the vector.
            let blind_result =
                VoprfClient::<Ristretto255>::deterministic_blind_unchecked(&input, blind).unwrap();
            assert_eq!(
                hex::encode(blind_result.message.serialize()),
                v.blinded_element,
                "BlindedElement"
            );
            // The evaluation element is deterministic (skS * blinded); the DLEQ
            // proof is randomized, so it is checked cryptographically via
            // finalize rather than byte-compared.
            let eval = server.blind_evaluate(&mut rand_core::OsRng, &blind_result.message);
            assert_eq!(
                hex::encode(eval.message.serialize()),
                v.evaluation_element,
                "EvaluationElement"
            );
            let output = blind_result
                .state
                .finalize(&input, &eval.message, &eval.proof, pk)
                .expect("finalize (incl. DLEQ verification) must succeed");
            assert_eq!(hex::encode(output), v.output, "Output");
            // The unblinded server-side evaluation must agree byte-for-byte.
            assert_eq!(hex::encode(server.evaluate(&input).unwrap()), v.output);
        }
    }

    #[test]
    fn dleq_proof_from_wrong_key_fails_finalize() {
        let server = rfc_server();
        let other =
            VoprfServer::<Ristretto255>::new_from_seed(&[0x11u8; 32], RFC_KEY_INFO).unwrap();
        let input = b"input";
        let blind_result =
            VoprfClient::<Ristretto255>::blind(input, &mut rand_core::OsRng).unwrap();
        let eval = other.blind_evaluate(&mut rand_core::OsRng, &blind_result.message);
        // Finalizing against the RFC server's public key with an evaluation
        // from a DIFFERENT key must fail the DLEQ check.
        assert!(blind_result
            .state
            .finalize(input, &eval.message, &eval.proof, server.get_public_key())
            .is_err());
    }

    // -----------------------------------------------------------------------
    // Minister ecosystem frozen vectors (fixed test master seed). These are
    // cross-repo fixtures: the interop harness (interop/prf-vectors.json) and
    // the Minister-side CI job assert the same bytes. Value-stable forever.
    // -----------------------------------------------------------------------

    /// 32 bytes, ASCII. Test fixture only — never a production seed.
    pub const TEST_MASTER_SEED: &[u8; 32] = b"MINISTER-TEST-VECTOR-SEED-0001!!";

    fn test_keys() -> PrfKeys {
        PrfKeys::from_seed(*TEST_MASTER_SEED, None).unwrap()
    }

    #[test]
    fn frozen_ecosystem_vectors() {
        let keys = test_keys();
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../interop/prf-vectors.json")).unwrap();
        assert_eq!(
            hex::encode(TEST_MASTER_SEED),
            vectors["master_seed_hex"].as_str().unwrap()
        );
        assert_eq!(
            keys.public_key_b64(),
            vectors["public_key_b64url"].as_str().unwrap(),
            "pkS derived from the frozen test seed drifted"
        );
        let sybil_id = vectors["dedup"]["sybil_id"].as_str().unwrap();
        let badge_type = vectors["dedup"]["badge_type"].as_str().unwrap();
        let input = dedup_input(sybil_id, badge_type);
        assert_eq!(
            hex::encode(&input),
            vectors["dedup"]["input_hex"].as_str().unwrap(),
            "stage-1 LP input encoding drifted"
        );
        let n_dedup = keys.evaluate_unblinded(&input).unwrap();
        assert_eq!(n_dedup.len(), DEDUP_VALUE_LEN);
        assert_eq!(
            hex::encode(&n_dedup),
            vectors["dedup"]["n_dedup_hex"].as_str().unwrap(),
            "N_dedup drifted — this value is forever"
        );
        let client_id = vectors["disclose"]["client_id"].as_str().unwrap();
        assert_eq!(
            keys.disclose(&n_dedup, client_id),
            vectors["disclose"]["n_rp"].as_str().unwrap(),
            "N_rp drifted — this value is forever"
        );
    }

    #[test]
    fn disclose_is_per_rp_and_versioned() {
        let keys = test_keys();
        let n_dedup = [0x42u8; DEDUP_VALUE_LEN];
        let a = keys.disclose(&n_dedup, "mc_client_a");
        let b = keys.disclose(&n_dedup, "mc_client_b");
        assert_ne!(a, b, "different RPs must receive unlinkable nullifiers");
        assert_eq!(a, keys.disclose(&n_dedup, "mc_client_a"), "deterministic");
        for v in [&a, &b] {
            assert!(v.starts_with(NULLIFIER_PREFIX));
            let tail = &v[NULLIFIER_PREFIX.len()..];
            assert_eq!(tail.len(), 43, "base64url(32 bytes), no padding");
            assert!(tail
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        }
        // Different N_dedup under the same RP: different value.
        assert_ne!(a, keys.disclose(&[0x43u8; DEDUP_VALUE_LEN], "mc_client_a"));
    }

    // -----------------------------------------------------------------------
    // Minister golden pairwise vectors (Phase 0, frozen in Minister's
    // oidc-claims.pairwise.test.ts). Cross-repo byte-equality fixtures.
    // -----------------------------------------------------------------------

    pub const GOLDEN_PAIRWISE_SECRET: &[u8] = b"minister-golden-vector-secret-v1-do-not-change!!";

    pub const GOLDEN_PAIRWISE_VECTORS: [(&str, &str); 4] = [
        (
            "user_golden_0001:mc_golden_client_0001",
            "xOfT05jnZI0r8hweyDLf7GnlAlPoUhHHoUsKH49Olm0",
        ),
        (
            "jti:badge_golden_0001:mc_golden_client_0001",
            "5fIc0YcinsYRBEf1J6aZXcoKuxmDStXGch6Rk_bDylM",
        ),
        (
            "sharelink:user_golden_0001:share_golden_0001",
            "3Wfr4iEXijtFDIQ9JkYamk6r427jpcY4ApbNbShi9sY",
        ),
        (
            "jti:sharelink:badge_golden_0001:share_golden_0001",
            "8ITdmHQXFlAukLUGdhAOqexFVwIEbnQFKvOnHy3LoOo",
        ),
    ];

    #[test]
    fn minister_golden_pairwise_vectors_byte_equal() {
        assert_eq!(GOLDEN_PAIRWISE_SECRET.len(), 48);
        let keys = PrfKeys::from_seed(
            *TEST_MASTER_SEED,
            Some(Zeroizing::new(GOLDEN_PAIRWISE_SECRET.to_vec())),
        )
        .unwrap();
        for (input, expected) in GOLDEN_PAIRWISE_VECTORS {
            assert_eq!(
                keys.pairwise(input.as_bytes()).unwrap(),
                expected,
                "pairwise vector for {input:?} drifted — cutover byte-stability broken"
            );
        }
    }

    #[test]
    fn pairwise_without_imported_secret_is_none() {
        let keys = test_keys();
        assert!(!keys.has_pairwise());
        assert!(keys.pairwise(b"anything").is_none());
    }

    #[test]
    fn evaluate_rejects_garbage_elements() {
        let keys = test_keys();
        // Wrong length.
        assert_eq!(keys.evaluate(&[0u8; 31]).unwrap_err(), PrfError::BadElement);
        // 32 bytes that are not a canonical ristretto255 encoding.
        assert_eq!(
            keys.evaluate(&[0xffu8; 32]).unwrap_err(),
            PrfError::BadElement
        );
        // The identity element must be rejected (RFC 9497 requires it).
        assert_eq!(keys.evaluate(&[0u8; 32]).unwrap_err(), PrfError::BadElement);
    }

    #[test]
    fn evaluate_roundtrip_matches_unblinded_and_verifies_dleq() {
        let keys = test_keys();
        let input = dedup_input("gh:987654321", "oauth-account");
        let blind_result =
            VoprfClient::<Ristretto255>::blind(&input, &mut rand_core::OsRng).unwrap();
        let out = keys
            .evaluate(&blind_result.message.serialize())
            .expect("valid blinded element evaluates");
        assert_eq!(out.evaluation_element.len(), ELEMENT_LEN);
        assert_eq!(out.proof.len(), PROOF_LEN);
        let eval_elt =
            voprf::EvaluationElement::<Ristretto255>::deserialize(&out.evaluation_element).unwrap();
        let proof = voprf::Proof::<Ristretto255>::deserialize(&out.proof).unwrap();
        let pk = voprf::VoprfServer::<Ristretto255>::new_from_seed(
            // reconstruct pk from the same seed path to prove pin stability
            &{
                let hk = Hkdf::<Sha512>::new(None, TEST_MASTER_SEED);
                let mut s = [0u8; 32];
                hk.expand(INFO_NULLIFIER_SEED, &mut s).unwrap();
                s
            },
            INFO_DEDUP_KEYPAIR,
        )
        .unwrap()
        .get_public_key();
        let output = blind_result
            .state
            .finalize(&input, &eval_elt, &proof, pk)
            .expect("client-side finalize incl. DLEQ verification");
        assert_eq!(output.to_vec(), keys.evaluate_unblinded(&input).unwrap());
    }
}
