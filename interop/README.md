# Interop proof: Rust signer ⇄ `@cloudflare/blindrsa-ts`

This harness proves that signatures produced by Signet (Rust,
`blind-rsa-signatures` crate, suite `RSAPBSSA-SHA384-PSS-Randomized`) interoperate
with the exact TypeScript library FreedInk uses to verify vote tokens
(`@cloudflare/blindrsa-ts`, `RSAPBSSA.SHA384.PSS.Randomized`), binding the public
metadata `freedink-vote:<version_id>`.

It exercises the **production data path**:

1. Rust generates a per-group master keypair (safe primes, full-length modulus)
   and exports the SPKI public key.
2. The TS client imports that SPKI and **blinds** a random nonce under the
   version metadata (this is what FreedInk's browser does).
3. Rust **blind-signs** the TS-produced blinded message with the metadata-derived
   key (this is what Signet's `/sign` does).
4. The TS client **finalizes and verifies** the signature (this is what
   FreedInk's redemption verifier does).

It also checks **cross-version binding**: a signature issued under `post-v1`
must fail to verify under `post-v2`.

## Run

```sh
# from the repo root
./interop/run.sh
```

Requirements: a Rust toolchain and Node.js. The Node verifier resolves
`@cloudflare/blindrsa-ts` from `interop/node/node_modules` (install with
`npm --prefix interop/node install`), pinned to the same version FreedInk uses.

A passing run prints `INTEROP OK` and exits 0. Any verification failure or
cross-version leak exits non-zero.

# Interop proof: Rust VOPRF ⇄ `@cloudflare/voprf-ts` (`prf.mjs`)

The second harness is the **ciphersuite decision gate** for the Minister
nullifier surface (RFC 9497 VOPRF, mode 0x01, ristretto255-SHA512): it proves
the Rust server (`voprf` crate, the exact `PrfKeys::evaluate` path
`/prf/evaluate` runs) interoperates with the TS client Minister will use
(`@cloudflare/voprf-ts` with the `@noble/curves` CryptoProvider), byte-exact
against the frozen ecosystem vectors in `prf-vectors.json`.

1. TS `DeriveKeyPair` independently reproduces the frozen `pkS` from the
   frozen test master seed (RFC 9497 §3.2.1 key schedule).
2. TS **blinds** the frozen dedup input; Rust **blind-evaluates** it and
   returns the evaluation element plus a DLEQ proof.
3. TS **finalizes**, verifying the Rust DLEQ proof against the pinned `pkS`,
   and the output must equal the frozen `N_dedup` byte-for-byte.
4. Adversarial checks: a tampered Rust proof and an evaluation under a
   different key must be **rejected** by the TS DLEQ verifier.
5. The stage-2 disclose `N_rp` and the pairwise golden vectors are reproduced
   with Node's own HKDF/HMAC as an extra cross-language check.

## Run

```sh
# from the repo root
./interop/run-prf.sh
```

The TS deps resolve from `interop/node_modules` (install with
`npm --prefix interop install`), pinned exact. A passing run prints
`PRF INTEROP OK` and exits 0; ANY red check exits non-zero — per the build
plan, a red gate means flipping the ciphersuite to P256-SHA256 before
anything depends on persisted values.
