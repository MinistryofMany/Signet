//! Partially-blind RSA signing, interoperable with FreedInk's verifier.
//!
//! Scheme: RSAPBSSA-SHA384-PSS-Randomized (RFC 9474 + the public-metadata
//! extension, draft-amjad-cfrg-partially-blind-rsa). The public metadata is the
//! version info string `freedink-vote:<version_id>` (see [`version_info`]).
//!
//! INTEROP: proven against `@cloudflare/blindrsa-ts`
//! `RSAPBSSA.SHA384.PSS.Randomized` (the library FreedInk runs). A blinded
//! message produced by the TS client, signed here, and finalized+verified by
//! the TS client round-trips. The metadata key-derivation (HKDF-SHA384 over
//! `"key"||info||0x00` with salt = n, info = "PBRSA"), the raw blind-sign
//! (`s = m^d' mod n`), and the SPKI public-key encoding are byte-identical to
//! the TS library. See `interop/` for the cross-check harness.
//!
//! ANONYMITY: the only message this module ever signs is the already-blinded
//! integer supplied by the caller. It performs a raw modular exponentiation on
//! that integer; it never sees, derives, or reconstructs the unblinded token
//! nonce.

use blind_rsa_signatures::pbrsa::{
    DefaultRng, PartiallyBlindKeyPair, PartiallyBlindPublicKey, PartiallyBlindSecretKey,
};
use blind_rsa_signatures::reexports::rsa::traits::PublicKeyParts;
use blind_rsa_signatures::{Error as BrsaError, Randomized, Sha384, PSS};

/// Concrete suite types fixed to RSAPBSSA-SHA384-PSS-Randomized.
type KeyPair = PartiallyBlindKeyPair<Sha384, PSS, Randomized>;
type SecretKey = PartiallyBlindSecretKey<Sha384, PSS, Randomized>;
type PublicKey = PartiallyBlindPublicKey<Sha384, PSS, Randomized>;

/// The public-metadata byte string FreedInk binds for a version.
///
/// MUST match `versionInfo` in FreedInk's `vote-token.ts`:
/// `freedink-vote:<versionId>`, UTF-8. Both sides derive the per-metadata key
/// from these exact bytes; any divergence makes signatures fail to verify.
///
/// CLIENT NOTE (for anyone using `blind-rsa-signatures` as the client, e.g. in
/// tests): unlike `@cloudflare/blindrsa-ts` — whose `blind()` derives the
/// per-metadata public key internally — this crate's `blind()`/`finalize()` use
/// whatever public key they are called on. A client must therefore call
/// `pk.derive_public_key_for_metadata(info)` and blind/finalize against the
/// DERIVED key. The on-the-wire bytes are identical to the TS library either
/// way (interop is proven in `interop/`); only the Rust API surface differs.
/// The server side here is unaffected: [`blind_sign`] derives the secret key
/// before signing.
pub fn version_info(version_id: &str) -> Vec<u8> {
    format!("freedink-vote:{version_id}").into_bytes()
}

/// A freshly generated group keypair, ready to be persisted. The private key is
/// PKCS#8 DER (to be encrypted at rest); the public key is SPKI DER (served in
/// clear).
pub struct GeneratedKey {
    pub pkcs8_der: Vec<u8>,
    pub spki_der: Vec<u8>,
}

/// Generate a new master keypair for a group.
///
/// Uses safe primes as required by the partially-blind scheme. This is CPU
/// intensive (seconds in release, longer in debug); callers should expect
/// latency and run it off the request hot path where possible.
///
/// INTEROP-CRITICAL: the modulus is regenerated until it is EXACTLY `bits`
/// bits (a full byte length). The crate's safe-prime keygen can yield a modulus
/// one or two bits short (e.g. 2047 bits), but FreedInk's `@cloudflare/blindrsa-ts`
/// derives `kLen = ceil(modulusLengthBits / 8)` from the WebCrypto-reported
/// `modulusLength`; a short modulus makes the client's `blind()` fail with
/// "number does not fit in N bytes" because the blinding factor inverse no
/// longer fits. Enforcing a full-length modulus keeps both sides in lockstep.
/// A bounded retry guards against the (vanishingly unlikely) pathological case
/// of never drawing a full-length modulus.
pub fn generate_group_key(bits: usize) -> Result<GeneratedKey, String> {
    const MAX_ATTEMPTS: usize = 64;
    for attempt in 0..MAX_ATTEMPTS {
        let kp =
            KeyPair::generate(&mut DefaultRng, bits).map_err(|e| format!("keygen failed: {e}"))?;
        let n_bits = kp.pk.as_ref().n().bits() as usize;
        if n_bits != bits {
            tracing::debug!(
                got = n_bits,
                want = bits,
                attempt,
                "regenerating key: modulus not full length"
            );
            continue;
        }
        let pkcs8_der = kp
            .sk
            .to_der()
            .map_err(|e| format!("PKCS#8 export failed: {e}"))?;
        let spki_der = kp
            .pk
            .to_der()
            .map_err(|e| format!("SPKI export failed: {e}"))?;
        return Ok(GeneratedKey {
            pkcs8_der,
            spki_der,
        });
    }
    Err(format!(
        "failed to generate a full {bits}-bit modulus after {MAX_ATTEMPTS} attempts"
    ))
}

/// Blind-sign a caller-supplied blinded message under the version metadata.
///
/// `pkcs8_der` is the decrypted master private key. `blinded_message` is the
/// raw blinded integer bytes from the client (exactly modulus-length). The
/// returned blind signature is modulus-length bytes. This does NOT unblind and
/// cannot recover the nonce.
///
/// The crate derives the per-metadata secret exponent `d'` and computes
/// `s = m^d' mod n`, internally re-checking `m == s^e' mod n` before returning
/// (defends against fault attacks).
pub fn blind_sign(
    pkcs8_der: &[u8],
    version_id: &str,
    blinded_message: &[u8],
) -> Result<Vec<u8>, BrsaError> {
    let sk = SecretKey::from_der(pkcs8_der)?;
    let pk = sk.public_key()?;
    let kp = KeyPair { pk, sk };
    let info = version_info(version_id);
    let derived = kp.derive_key_pair_for_metadata(&info)?;
    let sig = derived.sk.blind_sign(blinded_message)?;
    // BlindSignature is a newtype over Vec<u8>; take the inner bytes.
    Ok(sig.0)
}

/// Load an SPKI DER public key (validation helper; also used in tests).
pub fn public_key_from_spki(spki_der: &[u8]) -> Result<PublicKey, BrsaError> {
    PublicKey::from_der(spki_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2048-bit safe-prime keygen is slow; generate once and reuse across the
    // crypto self-consistency checks.
    fn key() -> GeneratedKey {
        generate_group_key(2048).unwrap()
    }

    #[test]
    fn version_info_matches_freedink_format() {
        assert_eq!(version_info("post-v1"), b"freedink-vote:post-v1");
    }

    #[test]
    fn full_roundtrip_self_consistent() {
        // Mirror the production split using the crate's own client primitives:
        // derive pubkey, blind, sign (service), finalize, verify.
        let k = key();
        let pk = public_key_from_spki(&k.spki_der).unwrap();
        let sk = SecretKey::from_der(&k.pkcs8_der).unwrap();
        let kp = KeyPair {
            pk,
            sk,
        };
        let info = version_info("post-v1");
        let derived = kp.derive_key_pair_for_metadata(&info).unwrap();

        let msg = b"unblinded-token-nonce";
        let blinding = derived
            .pk
            .blind(&mut DefaultRng, msg, Some(&info))
            .unwrap();

        // Service path: only the master PKCS#8 + blinded message + version_id.
        let blind_sig = blind_sign(&k.pkcs8_der, "post-v1", blinding.blind_message.as_ref())
            .unwrap();
        let blind_sig = blind_rsa_signatures::BlindSignature(blind_sig);

        let sig = derived
            .pk
            .finalize(&blind_sig, &blinding, msg, Some(&info))
            .unwrap();
        derived
            .pk
            .verify(&sig, blinding.msg_randomizer, msg, Some(&info))
            .unwrap();
    }

    #[test]
    fn cross_version_metadata_binding_fails() {
        // A token blinded+signed under v1 must NOT verify under v2.
        let k = key();
        let sk = SecretKey::from_der(&k.pkcs8_der).unwrap();
        let pk = public_key_from_spki(&k.spki_der).unwrap();
        let kp = KeyPair {
            pk,
            sk,
        };
        let info_v1 = version_info("post-v1");
        let derived_v1 = kp.derive_key_pair_for_metadata(&info_v1).unwrap();

        let msg = b"nonce";
        let blinding = derived_v1
            .pk
            .blind(&mut DefaultRng, msg, Some(&info_v1))
            .unwrap();
        let blind_sig =
            blind_sign(&k.pkcs8_der, "post-v1", blinding.blind_message.as_ref()).unwrap();
        let blind_sig = blind_rsa_signatures::BlindSignature(blind_sig);
        let sig = derived_v1
            .pk
            .finalize(&blind_sig, &blinding, msg, Some(&info_v1))
            .unwrap();

        // Verify under v2 metadata: must fail.
        let info_v2 = version_info("post-v2");
        let derived_v2 = kp.derive_key_pair_for_metadata(&info_v2).unwrap();
        let res = derived_v2.pk.verify(&sig, blinding.msg_randomizer, msg, Some(&info_v2));
        assert!(res.is_err(), "v1 token must not verify under v2 metadata");
    }
}
