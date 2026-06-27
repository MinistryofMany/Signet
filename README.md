# Signet

Hardened **partially-blind RSA signing service** for FreedInk vote tokens. It
holds each blog's issuer key, blind-signs the **already-blinded** message a
client sends, and enforces *one signature per `(group, participant, version)`*
plus rate limits. It is the policy/eligibility boundary that a compromised
relying party cannot bypass to mass-forge tokens.

It interoperates with FreedInk's existing verifier: suite
`RSAPBSSA-SHA384-PSS-Randomized` (RFC 9474 + the public-metadata extension,
`draft-amjad-cfrg-partially-blind-rsa`), public metadata
`freedink-vote:<version_id>` — the exact scheme `@cloudflare/blindrsa-ts` uses.

## The anonymity invariant

The service signs the **blinded message only**. It never receives, sees,
stores, or logs the unblinded token nonce. It does see
`(group_id, participant_id, version_id)` — the participation record ("participant
P asked for a token for version V"), not the vote. Because the signer only ever
touches the blinded message, neither it nor FreedInk can later link a redeemed
token (unblinded nonce + signature) back to a participant. The audit log records
only the identity tuple plus a timestamp — never the `blinded_message` or the
`blind_signature`.

## Endpoints (all require mTLS)

| Method | Path | Body / query | Returns |
| ------ | ---- | ------------ | ------- |
| `POST` | `/sign` | `{ group_id, participant_id, version_id, blinded_message }` (base64) | `{ blind_signature }` (base64) |
| `GET`  | `/key` | `?group_id=…` | `{ group_id, public_key, key_id }` (SPKI, base64) |
| `POST` | `/key` | `?group_id=…` | create the group key if absent (idempotent) |
| `POST` | `/key/rotate` | `?group_id=…` | retire the active key, generate a fresh one |
| `GET`  | `/healthz` | — | `ok` |

`/sign` enforces, in order: rate limits (per-participant + global) → **record-first
reservation** (insert the issuance row before signing; a `UNIQUE(group_id,
participant_id, version_id)` index makes a concurrent double-issue lose the race)
→ blind-sign. If signing fails after reservation, the reservation is rolled back
so a transient error does not burn the participant's single token.

There is **no key-export endpoint**, ever. Private keys never leave the process
except as AES-256-GCM ciphertext written to the local DB.

## Crypto and interop

- Crate: [`blind-rsa-signatures`](https://crates.io/crates/blind-rsa-signatures)
  `0.17.2` (jedisct1), `pbrsa` module. It **natively supports public metadata**
  (`derive_key_pair_for_metadata`), and its metadata key-derivation
  (HKDF-SHA384 over `"key" || info || 0x00`, salt = modulus `n`, info `"PBRSA"`)
  is byte-identical to `@cloudflare/blindrsa-ts` and the IETF draft. We did not
  hand-roll any blinding.
- The signer performs only a raw modular exponentiation on the blinded integer
  with the metadata-derived private exponent (`s = m^d' mod n`), re-checking
  `m == s^e' mod n` internally before returning. It does no PSS encoding (the
  client already did that during `blind`).
- **Full-length modulus:** keys are regenerated until the modulus is exactly
  `SIGNET_KEY_BITS` bits. The crate's safe-prime keygen can yield a modulus a
  bit or two short (e.g. 2047 bits); the TS client derives `kLen` from the
  WebCrypto-reported `modulusLength` and a short modulus makes its `blind()`
  fail. Enforcing a full modulus keeps both sides in lockstep.

### Proving interop

`interop/run.sh` exercises the **production data path** against the real TS
library FreedInk uses (`@cloudflare/blindrsa-ts`, pinned `0.4.6`):

1. Rust generates a per-group key and exports SPKI.
2. The TS client blinds a nonce under `freedink-vote:<version>`.
3. Rust blind-signs the TS-produced blinded message.
4. The TS client finalizes + verifies — must succeed.

It also asserts cross-version binding (a v1 token must not verify under v2) and
that a server-side metadata mismatch is rejected at finalize. A passing run
prints `INTEROP OK`.

```sh
./interop/run.sh
```

## Build, test, run

```sh
cargo build --release            # build the service
cargo test --release             # unit + integration tests (mTLS, invariants, at-rest)
./interop/run.sh                 # cross-language interop proof (needs Node)
```

### Environment

| Var | Required | Default | Meaning |
| --- | -------- | ------- | ------- |
| `SIGNET_KEK` | **yes** | — | 32-byte key-encryption key (hex or base64). Encrypts private keys at rest. Held in memory only; never logged or returned. |
| `SIGNET_TLS_CERT` | **yes** | — | Server certificate chain (PEM). |
| `SIGNET_TLS_KEY` | **yes** | — | Server private key (PEM). |
| `SIGNET_CLIENT_CA` | **yes** | — | CA bundle (PEM) used to verify **client** certs. mTLS is mandatory. |
| `SIGNET_BIND` | no | `0.0.0.0:8443` | Listen address. |
| `SIGNET_DB` | no | `signet.db` | SQLite path. |
| `SIGNET_KEY_BITS` | no | `2048` | New-key modulus size (2048–4096, multiple of 16). |
| `SIGNET_AUTO_CREATE_KEYS` | no | `true` | Lazily create a group key on first `/sign` or `/key`. |
| `SIGNET_RL_PARTICIPANT_MAX` | no | `5` | Max issuances per participant per window. |
| `SIGNET_RL_GLOBAL_MAX` | no | `1000` | Max issuances across all participants per window. |
| `SIGNET_RL_WINDOW_SECS` | no | `60` | Rate-limit window length (seconds). |
| `RUST_LOG` | no | `info` | Log filter. |

Generate a KEK:

```sh
head -c32 /dev/urandom | base64        # or: head -c32 /dev/urandom | xxd -p -c64
```

### mTLS setup

The server presents its own cert AND requires a client cert chaining to
`SIGNET_CLIENT_CA`. A client with no cert, or a cert from an untrusted CA, is
refused at the TLS handshake — before any HTTP runs. Only the holder of a valid
client cert (FreedInk) can reach `/sign`.

Generate dev certs (pure Rust, no openssl):

```sh
./deploy/gen-dev-certs.sh           # writes deploy/certs/{ca,server,client}.{pem,key}
```

The server cert's SANs include `signet`, `localhost`, `127.0.0.1`, so it works
both on localhost and as `https://signet:8443` inside docker-compose. For
production, mint client certs from your real PKI and keep the CA key offline.

### docker-compose (network isolation)

`deploy/docker-compose.yml` puts the signer on an `internal: true` docker
network with **no host port published**. It is reachable only as
`https://signet:8443` from services co-attached to `signet-internal` (i.e.
FreedInk). Nothing on the host can route to it.

```sh
cp .env.example .env                # set SIGNET_KEK
./deploy/gen-dev-certs.sh
docker compose -f deploy/docker-compose.yml up --build
```

Merge the `freedink` block into your real FreedInk compose; the load-bearing
parts are the `signet-internal` attachment and the client-cert mount.

## FreedInk integration contract (follow-up, not done here)

This pass builds the service only. To wire FreedInk in (separate branch):

- **Mapping:** `group_id` = blog id; `participant_id` = the stable user id used
  for FreedInk's per-`(user, version)` review check; `version_id` = the post
  version id.
- **Metadata:** the public metadata bytes are `freedink-vote:<version_id>`,
  matching `versionInfo()` in FreedInk's `src/lib/{server,client}/vote-token.ts`.
  Do not change this string on either side without changing both.
- **Issuance:** FreedInk's `/api/blog/vote-token` handler stops signing locally.
  It calls `POST /sign` on Signet (over mTLS, presenting its client cert) with
  the blinded message the browser produced, and returns the `blind_signature`
  to the client unchanged. Keep FreedInk's `can_review` eligibility check too —
  defense in depth — but the signer is the hard cap.
- **Public key:** FreedInk fetches the issuer public key from `GET /key?group_id=<blog>`
  (or caches it in `blog_vote_token_keys`, public-key-only). It no longer stores
  any private key. Redemption verifies the unblinded signature against this
  public key exactly as today.
- **Issuer host coupling:** the public key Signet serves IS the verification key;
  there is no `did:web` derivation here (that coupling is Discreetly's, not
  FreedInk's).

## Security notes for an auditor

- **Interop is proven** against the real `@cloudflare/blindrsa-ts` in both
  directions (Rust-signs/TS-verifies and TS-blinds/Rust-signs/TS-finalizes), plus
  cross-version binding. See `interop/`.
- **Private keys at rest** are AES-256-GCM sealed under the env KEK, with the
  `(group_id, key_id)` bound as additional authenticated data; the DB never
  holds plaintext PKCS#8 (`tests/at_rest.rs` asserts this).
- **mTLS** is mandatory; a certless client is rejected at the handshake
  (`tests/mtls.rs`).
- **One-per-tuple** holds under concurrency via record-first + a UNIQUE index
  (`tests/issuance.rs::concurrent_same_tuple_yields_exactly_one_success`).
- The KEK lives only in process memory and is zeroized on drop; it is never
  logged, returned, or written to the DB.
