//! PRF interop CLI used by `interop/prf.mjs` to prove cross-language VOPRF
//! compatibility with `@cloudflare/voprf-ts`. Not part of the service binary.
//!
//! Usage: `prf_interop_tool <prf-vectors.json> <blinded_element_hex>`
//!
//! Loads the FROZEN TEST master seed from the vectors file (never a
//! production seed), derives the key schedule exactly as the service does
//! (`signet::prf::PrfKeys`), blind-evaluates the supplied element — the same
//! code path `/prf/evaluate` runs — and prints:
//!
//! ```text
//! pk=<hex pkS>
//! eval=<hex evaluation element>
//! proof=<hex DLEQ proof (c || s)>
//! ```

use signet::prf::{PrfKeys, MASTER_SEED_LEN};

fn main() {
    let usage = "usage: prf_interop_tool <prf-vectors.json> <blinded_element_hex>";
    let vectors_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("{usage}");
        std::process::exit(2);
    });
    let blinded_hex = std::env::args().nth(2).unwrap_or_else(|| {
        eprintln!("{usage}");
        std::process::exit(2);
    });

    let raw = std::fs::read_to_string(&vectors_path).expect("cannot read the vectors file");
    let vectors: serde_json::Value = serde_json::from_str(&raw).expect("vectors file is not JSON");
    let seed_hex = vectors["master_seed_hex"]
        .as_str()
        .expect("vectors file lacks master_seed_hex");
    let seed_bytes = hex::decode(seed_hex).expect("master_seed_hex is not hex");
    assert_eq!(
        seed_bytes.len(),
        MASTER_SEED_LEN,
        "frozen test seed must be {MASTER_SEED_LEN} bytes"
    );
    let mut seed = [0u8; MASTER_SEED_LEN];
    seed.copy_from_slice(&seed_bytes);

    let keys = PrfKeys::from_seed(seed, None).expect("key schedule derivation failed");
    let blinded = hex::decode(blinded_hex.trim()).expect("blinded element is not hex");
    let out = keys
        .evaluate(&blinded)
        .expect("blinded element is not a valid group element");

    println!("pk={}", hex::encode(keys.public_key_bytes()));
    println!("eval={}", hex::encode(out.evaluation_element));
    println!("proof={}", hex::encode(out.proof));
}
