# Crypto-core operations (VOPRF / dedup nullifier)

Signet is dual-purpose. `README.md` and `deploy/` document its original job:
partially-blind RSA signing for FreedInk vote tokens. This doc covers the
second job, added later: the crypto-core PRF/dedup surface (RFC 9497 VOPRF
nullifiers plus the pairwise HMAC oracle) that Minister uses at badge
issuance to deduplicate a claim (e.g. one GitHub account, one badge) without
ever showing Minister the raw dedup anchor.

It's a provisioning runbook, not an architecture doc — for how the PRF
surface itself works, read the doc comments in `src/dedup.rs`, `src/prf.rs`,
and `src/identity.rs`. This assumes the reader already has the `signet`
binary/image and is standing up a real deployment (the first Lightsail
prod rollout is the reference case throughout).

## The dual-purpose split, and how it stays inert

One binary, one image, two surfaces gated by separate config:

- **Blind-RSA signing** (`/sign`, `/key*`) — FreedInk's job. Governed by
  `SIGNET_ALLOWED_CLIENT_IDS` / `SIGNET_ADMIN_IDS` / `SIGNET_AUTO_CREATE_KEYS`.
- **PRF/dedup** (`/prf/*`, `/dedup/*`) — Minister's job. Governed by
  `SIGNET_PRF_CLIENT_IDS`, completely separate from the signing allow-lists
  (see `src/identity.rs`: PRF authorization is never implied by the client
  list or its open back-compat mode).

A deployment that only wants the crypto-core surface — Minister, today —
must deliberately keep the signing surface inert:

- `SIGNET_ALLOWED_CLIENT_IDS` set to a placeholder no real certificate will
  ever match (e.g. `reserved-no-sign-clients`), so Minister's own client
  cert can never be classified into the `Client` role and reach `/sign`.
- `SIGNET_AUTO_CREATE_KEYS=false`, so nothing lazily mints an RSA signing key
  even if `/sign` or `/key` were somehow reached.
- `SIGNET_ADMIN_IDS` left unset, which fail-closed disables `/key/rotate`
  for everyone.

Minister's mTLS client cert (CN `prf-minister`) is listed only in
`SIGNET_PRF_CLIENT_IDS`. That admits it with the restricted `Prf` role:
`/prf/*` and `/dedup/*` only, `may_sign()` false. See gotcha 2 below — this
is easy to get backwards.

## mTLS PKI

The PRF surface is reached over the same mandatory mTLS as the signing
surface (`src/tls.rs` — no client cert, no connection). For a real
deployment, generate a dedicated PKI rather than the dev certs from
`deploy/gen-dev-certs.sh` (those are rcgen-generated, CN-locked to
`freedink`/`signet-admin`, and meant for local/CI use only).

The first Lightsail rollout used plain `openssl`, ECDSA P-256, three
certs:

1. **CA** — `CN=Signet Prod CA`, `basicConstraints=CA:TRUE,pathlen:0`,
   `keyUsage=keyCertSign,cRLSign`. Signet-only: this CA must never also sign
   certs for anything unrelated, or any cert it issues could attempt to
   connect (mTLS chain validation is necessary but not sufficient — see
   `src/identity.rs`'s module doc on why identity pinning exists on top of
   it). Keep `ca.key` offline once the leaf certs are issued.
2. **Server cert** — `CN=signet`, **`SAN=DNS:signet`**, `extendedKeyUsage`
   `serverAuth`, `keyUsage=digitalSignature`. The SAN has to be the exact
   DNS name the caller dials (see gotcha 4).
3. **Minister's client cert** — `CN=prf-minister`, `extendedKeyUsage`
   `clientAuth`. This is the identity that goes into
   `SIGNET_PRF_CLIENT_IDS`.

```sh
umask 077
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 3650 \
  -subj "/CN=Signet Prod CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.pem

openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=signet" \
  -addext "subjectAltName=DNS:signet" -out server.csr
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 1095 -sha256 \
  -extfile <(printf "subjectAltName=DNS:signet\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature") \
  -out server.pem

openssl ecparam -name prime256v1 -genkey -noout -out minister-client.key
openssl req -new -key minister-client.key -subj "/CN=prf-minister" -out minister-client.csr
openssl x509 -req -in minister-client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 1095 -sha256 \
  -extfile <(printf "extendedKeyUsage=clientAuth") \
  -out minister-client.pem

openssl verify -CAfile ca.pem server.pem minister-client.pem
```

Verify the SAN and CN landed correctly before deploying:

```sh
openssl x509 -in server.pem -noout -subject -ext subjectAltName
openssl x509 -in minister-client.pem -noout -subject
```

Permissions: `server.key` must be readable by the container's uid (the
Dockerfile runs as a non-root `signet` user, uid `10001` — `chown 10001
server.key; chmod 400 server.key`). Every private key mode `600` on the
host, `ca.key` in particular kept out of the running deployment entirely
once the leaf certs exist.

Leaf certs above run ~3 years, the CA ~10 — calendar the expiry and refresh
the SSM custody entries (below) whenever you re-issue.

## Crypto-core environment

These are on top of the base env Signet already documents in `README.md`
(`SIGNET_TLS_CERT`, `SIGNET_TLS_KEY`, `SIGNET_CLIENT_CA`, `SIGNET_DB`,
`SIGNET_BIND`, ...):

| Var | Meaning |
| --- | --- |
| `SIGNET_KEK` | Same KEK as the signing surface — seals the VOPRF master seed at rest (`src/dedup.rs`), same 32-byte hex-or-base64 encoding. `openssl rand -hex 32`. |
| `SIGNET_DB` | SQLite path (`/data/signet.db` in the container). Same file backs both surfaces' tables. |
| `SIGNET_PRF_CLIENT_IDS` | Comma-separated identities (cert CN/SAN) allowed to call `/prf/*` and `/dedup/*` — set to `prf-minister`. Empty means the PRF routes aren't mounted at all. |
| `SIGNET_DEDUP_PUBKEY_PIN` | The VOPRF public key `pkS` (43-char base64url, no padding) that `init-service-keys` prints. Required once `SIGNET_PRF_CLIENT_IDS` is non-empty; a mismatch refuses startup (key-fork guard). **Leave unset until after init** — see gotcha 3. |
| `SIGNET_ALLOWED_CLIENT_IDS` | Set to a placeholder no cert will match (e.g. `reserved-no-sign-clients`) so the PRF-only client can never also reach `/sign`. |
| `SIGNET_AUTO_CREATE_KEYS` | `false` — never lazily mint an RSA signing key on this deployment. |

## Provisioning: `init-service-keys`

The VOPRF master seed is minted exactly once, by the `init-service-keys`
one-shot (`src/main.rs`: `signet init-service-keys`, or
`SIGNET_INIT_SERVICE_KEYS=1`). It mints 32 bytes of OS randomness, seals
them under `SIGNET_KEK` into the `service_keys` table, prints the derived
public key `pkS` to stdout — and only `pkS`, never seed bytes — and exits.
It refuses outright if `SIGNET_DEDUP_PUBKEY_PIN` or
`SIGNET_IMPORT_PAIRWISE_HMAC` is already set (`src/dedup.rs`,
`check_init_preconditions`): a pinned node's seed exists elsewhere by
definition, so it must restore a keystore, never mint a fresh one.

Run it as a **direct `docker run`**, not `docker compose run` — on an
`internal: true` network, `docker compose run` hangs (gotcha 6). Init needs
only the KEK, the DB volume, and no network at all:

```sh
docker run --rm --network none \
  -v ministry_signet-data:/data \
  -e SIGNET_KEK="$SIGNET_KEK" \
  -e SIGNET_DB=/data/signet.db \
  ghcr.io/ministryofmany/ministry-signet:latest \
  init-service-keys
```

(`ministry_signet-data` assumes the compose project is `-p ministry` — a
named volume is prefixed with the project name unless declared `external`.
Adjust to match your project name.)

The last line of output is the 43-character `pkS`. Pin it on **both sides**:

- Signet: `SIGNET_DEDUP_PUBKEY_PIN=<pkS>` (uncomment the line in
  `docker-compose.lightsail.yml`, restart `signet`).
- Minister: `MINISTER_SIGNET_DEDUP_PUBKEY=<pkS>` (its own pin, checked
  independently by `verifyPin` at boot — see the wire contract in
  `Minister/apps/minister/src/lib/nullifier/README.md`).

Once both are pinned, a re-run of `init-service-keys` refuses (`service
keys are already initialized`) — that refusal is the intended never-rotate
behavior, not a bug.

## Custody

Everything the seed's confidentiality depends on lives in AWS SSM under
**`/signet/prod/*`** — deliberately **not** `/minister/prod` (gotcha 1):

- `SIGNET_KEK` (SecureString)
- The sealed master-seed blob (SecureString, hex — read from the
  `service_keys` table, see below)
- `SIGNET_DEDUP_PUBKEY_PIN` (String — it's a public key, not a secret, but
  keeping it alongside the KEK/blob makes restoring a replica a single SSM
  pull)

Pulling the sealed blob for backup (read-only, no KEK needed to read the
ciphertext column). Unlike `init-service-keys`, this needs real network
(`apk` fetches the package index), so don't run it with `--network none`:

```sh
docker run --rm -v ministry_signet-data:/data alpine:3.20 \
  sh -c "apk update -q && apk add -q sqlite && sqlite3 'file:/data/signet.db?mode=ro' \
    \"SELECT purpose, hex(sealed), created_at FROM service_keys;\""
```

Also back up the whole sealed DB off-box (`sqlite3 ... .backup`,
`scp`/equivalent to durable storage) alongside the CA key. Neither the
sealed blob nor the DB backup is useful without `SIGNET_KEK`, and `SIGNET_KEK`
by itself is useless without the sealed blob — but treat both as sensitive
custody material regardless.

Minister's side of the pairing (its mTLS client cert/key, the Signet CA
cert, and the pubkey pin) are separate SecureStrings under
`/minister/prod/MINISTER_SIGNET_CLIENT_CERT` /
`MINISTER_SIGNET_CLIENT_KEY` / `MINISTER_SIGNET_CA_CERT` /
`MINISTER_SIGNET_DEDUP_PUBKEY`.

## Network isolation model

Same shape as the signing deployment in `deploy/docker-compose.yml`, reused
for the crypto-core surface: `signet` sits on a docker network with
`internal: true` (no gateway, no egress, no host port published). Only
services co-attached to that network — in this deployment, Minister — can
resolve or route to `signet` at all. mTLS plus `SIGNET_PRF_CLIENT_IDS` is
still the authoritative access control; the network boundary is
defense-in-depth, not a substitute for it.

## Verifying a fresh deployment

Before flipping Minister's nullifier backend, confirm the mTLS path
end-to-end from a container on the same internal network, presenting
Minister's client cert:

```sh
curl --cacert ca.pem --cert minister-client.pem --key minister-client.key \
  https://signet:8443/prf/public-key
# expect: {"suite":"...","public_key":"<the pinned pkS>"}

curl https://signet:8443/prf/public-key
# expect: mTLS handshake failure (no client cert presented)
```

And from outside the internal network (default bridge, or the host):
expect a DNS/connect failure — the SAN is only resolvable/routable within
`signet-internal`.

## The 6 gotchas

1. **Custody secrets go under `/signet/prod`, never `/minister/prod`.**
   Minister's SSM loader injects the *entire* `/minister/prod` path into its
   own process environment. Putting `SIGNET_KEK` there would hand Minister's
   process the ability to decrypt Signet's sealed keys, collapsing the
   Minister-Signet trust boundary the whole mTLS split exists to enforce.
2. **Close the client allow-list, don't leave it open.** An unset
   `SIGNET_ALLOWED_CLIENT_IDS` classifies *any* CA-chained cert — including
   Minister's — into the signing `Client` role (`src/identity.rs`: empty
   list = back-compat open admission). Set it to a placeholder no real cert
   matches (`reserved-no-sign-clients`) and pair it with
   `SIGNET_AUTO_CREATE_KEYS=false`, so Minister's PRF-only cert stays
   PRF-only.
3. **A present-but-empty pin blocks init.** Compose's `${VAR}` syntax
   resolves a missing variable to an empty string, which still counts as
   "set" to `check_init_preconditions` — so a `SIGNET_DEDUP_PUBKEY_PIN:
   "${SIGNET_DEDUP_PUBKEY_PIN}"` line with the env var unset will refuse
   `init-service-keys` even though no real pin exists yet. Keep the pin line
   commented out of the compose file until `init-service-keys` has printed a
   real value, then uncomment it.
4. **The server cert's SAN must be exactly `DNS:signet`.** TLS hostname
   verification checks the SAN, not the CN, and the caller (Minister) dials
   the compose DNS name `signet`. A cert minted with a different SAN (e.g.
   the box's real hostname) fails verification even though the chain is
   otherwise valid.
5. **Once flipped to `signet`, Signet is a boot dependency for Minister.**
   `MINISTER_NULLIFIER_BACKEND=signet` means Minister's boot-time
   `verifyPin` check does a live mTLS fetch to Signet and throws on
   failure. A steady-state Signet outage only degrades badge issuance
   (login and token verification are unaffected), but restarting Minister
   *while* Signet is down will crash-loop the whole Minister process. If
   Signet needs to go down for maintenance, flip Minister back to
   `MINISTER_NULLIFIER_BACKEND=interim` first, or avoid restarting Minister
   until Signet is back.
6. **`docker compose run` hangs on an `internal: true` network.** Use a
   direct `docker run --network none ... init-service-keys` for the one-shot
   init instead (see above). Ordinary `docker compose up -d signet` is fine
   — only the interactive `run` orchestration hangs.
