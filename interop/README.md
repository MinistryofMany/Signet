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
