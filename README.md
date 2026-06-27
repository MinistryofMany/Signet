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

## Endpoints (all require mTLS + a pinned client identity)

| Method | Path | Body / query | Returns |
| ------ | ---- | ------------ | ------- |
| `POST` | `/sign` | `{ group_id, participant_id, version_id, blinded_message }` (base64) | `{ blind_signature }` (base64); `202 { status:"pending" }` if the key is still being generated |
| `GET`  | `/key` | `?group_id=…` | `200 { group_id, status:"ready", public_key, key_id }` (SPKI, base64) or `202 { group_id, status:"pending" }` |
| `POST` | `/key` | `?group_id=…` | enqueue key generation; `202 { status:"pending" }` (or `200` ready if one already exists). Idempotent + deduped per group |
| `POST` | `/key/rotate` | `?group_id=…` | **admin identity only**: retire the active key, generate a fresh one → `200 { status:"ready", … }` |
| `GET`  | `/healthz` | — | `ok` |

`/sign` enforces, in order: rate limits (per-participant + global) → **record-first
reservation** (insert the issuance row before signing; a `UNIQUE(group_id,
participant_id, version_id)` index makes a concurrent double-issue lose the race)
→ blind-sign. If signing fails after reservation, the reservation is rolled back
so a transient error does not burn the participant's single token.

### Async key generation (no cold-keygen request stall)

Safe-prime RSA keygen takes seconds, so key creation is **non-blocking**:
`POST /key` (and the auto-create path of `GET /key`) enqueue generation on a
bounded worker pool and return `202 pending` immediately; the caller **polls**
`GET /key` until it returns `200 ready`. Concurrent requests for the same
`group_id` are **deduped** to one generation, and a semaphore
(`SIGNET_KEYGEN_MAX_CONCURRENT`) caps how many keygens run at once — so a flood of
`/key` requests cannot spawn unbounded multi-second CPU work. `/sign` for a
not-yet-ready key waits a short bounded time and then returns `202 pending`
rather than holding a request thread for the full keygen. The `/key*` endpoints
are rate-limited per client identity and globally.

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
| `SIGNET_ALLOWED_CLIENT_IDS` | no | *(empty)* | Comma-separated client identities (cert CN or DNS SAN) allowed to call the signing/key endpoints. **Empty = any cert chaining to `SIGNET_CLIENT_CA` is accepted** (a warning is logged). Set this in production. |
| `SIGNET_ADMIN_IDS` | no | *(empty)* | Comma-separated admin identities allowed to call `/key/rotate`. **Empty = rotation is disabled for everyone** (fail-closed). |
| `SIGNET_KEYGEN_MAX_CONCURRENT` | no | `2` | Max concurrent key generations (bounded worker pool). |
| `SIGNET_RL_KEY_IDENTITY_MAX` | no | `10` | Max `/key*` requests per client identity per window. |
| `SIGNET_RL_KEY_GLOBAL_MAX` | no | `100` | Max `/key*` requests across all identities per window. |
| `RUST_LOG` | no | `info` | Log filter. |

Generate a KEK:

```sh
head -c32 /dev/urandom | base64        # or: head -c32 /dev/urandom | xxd -p -c64
```

### mTLS setup and client-identity pinning

The server presents its own cert AND requires a client cert chaining to
`SIGNET_CLIENT_CA`. A client with no cert, or a cert from an untrusted CA, is
refused at the TLS handshake — before any HTTP runs.

mTLS chain validation alone is **not** the access boundary: on top of it Signet
pins the peer's **identity** (the leaf cert's CN or a DNS SAN) and classifies it
into a role.

- **`SIGNET_CLIENT_CA` must be a dedicated, Signet-only client CA.** Because any
  certificate that chains to it can attempt to connect, this CA must sign *only*
  Signet client certs (FreedInk's, and your admin cert) — never reuse a shared
  org/web CA. Keep its key offline; mint client certs from it directly.
- **`SIGNET_ALLOWED_CLIENT_IDS`** restricts which identities may call the
  signing/key endpoints. A cert that chains to the CA but is not on this list is
  dropped at the connection. Leaving it empty accepts any valid-chain cert (a
  startup warning is logged); set it in production.
- **`SIGNET_ADMIN_IDS`** gates `/key/rotate` behind a *distinct admin identity*
  (a separate allowed CN, or an admin-only cert). A non-admin client gets `403`;
  with no admin identity configured, rotation is disabled for everyone.

**Rotation invalidates outstanding tokens.** `POST /key/rotate` retires the
group's active key and mints a new one. Any vote token signed under the retired
key will no longer verify against the now-current public key served by
`GET /key`. Rotate only when you intend to invalidate previously issued tokens
for that group (e.g. on suspected key compromise), and coordinate with FreedInk's
verification/redemption window.

Only the holder of an allow-listed client cert (FreedInk) can reach `/sign`.

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
  (`tests/mtls.rs`). On top of mTLS, the peer **identity** (cert CN/DNS SAN) is
  pinned: an off-allow-list cert is dropped at the connection, and `/key/rotate`
  requires a distinct admin identity (`tests/keygen_dos.rs`).
- **One-per-tuple** holds under concurrency via record-first + a UNIQUE index
  (`tests/issuance.rs::concurrent_same_tuple_yields_exactly_one_success`).
- **Keygen is bounded**: key creation is async with a semaphore-capped worker
  pool and per-group dedup, and the `/key*` endpoints are rate-limited, so a
  flood cannot spawn unbounded multi-second keygens (`tests/keygen_dos.rs`).
- The KEK lives only in process memory and is zeroized on drop; the raw encoded
  value is also zeroized and removed from the process environment after load. It
  is never logged, returned, or written to the DB.
- **Supply chain**: `deny.toml` + CI run `cargo deny check` (advisories,
  licenses, banned crates, sources). Two advisories are consciously accepted with
  documented reasons (the `rsa` Marvin-attack timing advisory, for which no fixed
  release exists, and the unmaintained `rustls-pemfile`); see `deny.toml`.
