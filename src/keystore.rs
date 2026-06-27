//! Private-key-at-rest encryption.
//!
//! Every group's RSA private key (PKCS#8 DER) is encrypted with AES-256-GCM
//! under a process-held KEK before it touches the database. The database never
//! sees plaintext PKCS#8. The KEK itself comes from the environment
//! (`SIGNET_KEK`) and is never written to the DB, logs, or any response.
//!
//! Wire format of an encrypted blob stored in the DB:
//!   version (1 byte = 0x01) || nonce (12 bytes) || ciphertext+tag
//! AES-GCM's tag authenticates the ciphertext; we additionally bind the group
//! id and key id as associated data so a ciphertext cannot be replayed under a
//! different identity.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

const BLOB_VERSION: u8 = 0x01;
const NONCE_LEN: usize = 12;

/// A 256-bit key-encryption key, zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Kek([u8; 32]);

impl Kek {
    /// Parse a KEK from a hex (64 chars) or base64 (standard or url-safe,
    /// padded or not) encoding of exactly 32 bytes.
    pub fn from_encoded(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let bytes = if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(s).map_err(|e| e.to_string())?
        } else {
            decode_base64_any(s).ok_or_else(|| "not valid hex or base64".to_string())?
        };
        if bytes.len() != 32 {
            return Err(format!("KEK must be 32 bytes, got {}", bytes.len()));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        let kek = Kek(k);
        // Wipe the temporary decode buffer.
        let mut bytes = bytes;
        bytes.zeroize();
        Ok(kek)
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0))
    }

    /// Encrypt `plaintext` (PKCS#8 DER private key) binding it to
    /// `(group_id, key_id)` as associated data.
    pub fn seal(&self, group_id: &str, key_id: i64, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = associated_data(group_id, key_id);
        let ct = self
            .cipher()
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| "AES-GCM encryption failed".to_string())?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(BLOB_VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a blob produced by [`seal`] for the same `(group_id, key_id)`.
    pub fn open(&self, group_id: &str, key_id: i64, blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.len() < 1 + NONCE_LEN + 16 {
            return Err("ciphertext too short".to_string());
        }
        if blob[0] != BLOB_VERSION {
            return Err(format!("unknown blob version {}", blob[0]));
        }
        let nonce = Nonce::from_slice(&blob[1..1 + NONCE_LEN]);
        let ct = &blob[1 + NONCE_LEN..];
        let aad = associated_data(group_id, key_id);
        self.cipher()
            .decrypt(nonce, Payload { msg: ct, aad: &aad })
            .map_err(|_| "AES-GCM decryption/authentication failed".to_string())
    }
}

fn associated_data(group_id: &str, key_id: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(group_id.len() + 8);
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(&key_id.to_be_bytes());
    aad
}

fn decode_base64_any(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> Kek {
        Kek::from_encoded(&hex::encode([7u8; 32])).unwrap()
    }

    #[test]
    fn roundtrip_seal_open() {
        let kek = test_kek();
        let pt = b"pretend-this-is-pkcs8-der";
        let blob = kek.seal("blog-1", 3, pt).unwrap();
        assert_ne!(
            &blob[1 + NONCE_LEN..],
            pt,
            "ciphertext must differ from plaintext"
        );
        let out = kek.open("blog-1", 3, &blob).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn aad_binding_rejects_wrong_identity() {
        let kek = test_kek();
        let blob = kek.seal("blog-1", 3, b"secret").unwrap();
        assert!(
            kek.open("blog-2", 3, &blob).is_err(),
            "wrong group must fail"
        );
        assert!(
            kek.open("blog-1", 4, &blob).is_err(),
            "wrong key id must fail"
        );
    }

    #[test]
    fn wrong_kek_fails() {
        let kek = test_kek();
        let blob = kek.seal("blog-1", 3, b"secret").unwrap();
        let other = Kek::from_encoded(&hex::encode([9u8; 32])).unwrap();
        assert!(other.open("blog-1", 3, &blob).is_err());
    }

    #[test]
    fn parses_hex_and_base64() {
        let raw = [42u8; 32];
        assert!(Kek::from_encoded(&hex::encode(raw)).is_ok());
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        assert!(Kek::from_encoded(&b64).is_ok());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(Kek::from_encoded(&hex::encode([0u8; 16])).is_err());
    }
}
