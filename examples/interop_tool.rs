//! Interop CLI used by `interop/run.sh` to prove cross-language compatibility
//! with `@cloudflare/blindrsa-ts`. Not part of the service binary.
//!
//! Modes:
//!   genkey            -> stdout JSON { spki, pkcs8 }  (base64; full-length modulus)
//!   sign              -> reads JSON { blinded_message, .. } on stdin, env PKCS8 + INFO,
//!                        echoes the object back with blind_signature added.
//!
//! These mirror exactly what the production service does in `crypto.rs`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blind_rsa_signatures::pbrsa::{DefaultRng, PartiallyBlindKeyPair, PartiallyBlindSecretKey};
use blind_rsa_signatures::reexports::rsa::traits::PublicKeyParts;
use blind_rsa_signatures::{BlindSignature, Randomized, Sha384, PSS};
use std::io::Read;

type KeyPair = PartiallyBlindKeyPair<Sha384, PSS, Randomized>;
type SecretKey = PartiallyBlindSecretKey<Sha384, PSS, Randomized>;

fn b64(b: &[u8]) -> String {
    B64.encode(b)
}
fn unb64(s: &str) -> Vec<u8> {
    B64.decode(s.trim()).expect("invalid base64")
}

/// Generate until the modulus is exactly `bits` bits (matches the service's
/// full-length-modulus requirement for TS interop).
fn gen_full(bits: usize) -> KeyPair {
    for _ in 0..64 {
        let kp = KeyPair::generate(&mut DefaultRng, bits).unwrap();
        if kp.pk.as_ref().n().bits() as usize == bits {
            return kp;
        }
    }
    panic!("could not generate a full {bits}-bit modulus");
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "genkey" => {
            let kp = gen_full(2048);
            let spki = kp.pk.to_der().unwrap();
            let pkcs8 = kp.sk.to_der().unwrap();
            println!(
                "{{\"spki\":\"{}\",\"pkcs8\":\"{}\"}}",
                b64(&spki),
                b64(&pkcs8)
            );
        }
        "sign" => {
            let pkcs8 = unb64(&std::env::var("PKCS8").expect("PKCS8 env required"));
            let info = std::env::var("INFO").expect("INFO env required");
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf).unwrap();
            let v: serde_json::Value = serde_json::from_str(&buf).expect("stdin not JSON");
            let blinded = unb64(v["blinded_message"].as_str().expect("blinded_message"));

            let sk = SecretKey::from_der(&pkcs8).unwrap();
            let pk = sk.public_key().unwrap();
            let kp = KeyPair { pk, sk };
            let derived = kp.derive_key_pair_for_metadata(info.as_bytes()).unwrap();
            let sig: BlindSignature = derived.sk.blind_sign(&blinded).unwrap();

            let mut out = v.clone();
            out["blind_signature"] = serde_json::Value::String(b64(&sig.0));
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        _ => {
            eprintln!("usage: interop_tool <genkey|sign>");
            std::process::exit(2);
        }
    }
}
