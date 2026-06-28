// Cross-language interop driver. Orchestrates the production data path between
// the Rust signer (invoked as the interop_tool example) and the real
// @cloudflare/blindrsa-ts library that FreedInk uses.
//
// Steps:
//   1. Rust genkey  -> SPKI + PKCS8
//   2. TS blind     (this script) under metadata <prefix>:<version>
//   3. Rust sign    -> blind_signature
//   4. TS finalize+verify (this script): must succeed
//   5. Cross-version: re-blind+sign under v1, verify under v2 must FAIL
//
// Checks run under the default `freedink-vote` prefix (byte-identical to
// FreedInk's wire format) and again under a `deforum-ban` prefix, proving that
// Signet's configurable SIGNET_INFO_PREFIX interops with the real TS library.
//
// Exit 0 and print "INTEROP OK" iff all checks pass.

import { RSAPBSSA } from '@cloudflare/blindrsa-ts';
import { webcrypto } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const subtle = webcrypto.subtle;
const SUITE = RSAPBSSA.SHA384.PSS.Randomized();

const RUST_BIN = process.env.SIGNET_INTEROP_BIN;
if (!RUST_BIN) {
  console.error('SIGNET_INTEROP_BIN must point at the built interop_tool binary');
  process.exit(2);
}

const b64 = (b) => Buffer.from(b).toString('base64');
const fromb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
// Public-metadata bytes: `<prefix>:<key>`, UTF-8. Mirrors Signet's version_info()
// and FreedInk's versionInfo (with prefix 'freedink-vote').
const buildInfo = (prefix, key) => new TextEncoder().encode(`${prefix}:${key}`);

function rust(mode, { env = {}, input } = {}) {
  const r = spawnSync(RUST_BIN, [mode], {
    env: { ...process.env, ...env },
    input,
    encoding: 'utf8',
    maxBuffer: 1 << 20,
  });
  if (r.status !== 0) {
    throw new Error(`rust ${mode} failed (status ${r.status}): ${r.stderr}`);
  }
  return r.stdout.trim();
}

async function importPub(spkiB64) {
  const spki = fromb64(spkiB64);
  return subtle.importKey('spki', spki.buffer, { name: 'RSA-PSS', hash: 'SHA-384' }, true, [
    'verify',
  ]);
}

// One full round trip: TS blind -> Rust sign -> TS finalize. Returns the
// finalized signature + prepared nonce so a caller can attempt cross-version
// verification. Throws if finalize's internal verification fails.
async function roundTrip({ spki, pkcs8, prefix, signKey, blindKey }) {
  const pk = await importPub(spki);
  const info = buildInfo(prefix, blindKey);
  const nonce = webcrypto.getRandomValues(new Uint8Array(32));
  const prepared = SUITE.prepare(nonce);
  const { blindedMsg, inv } = await SUITE.blind(pk, prepared, info);

  // The deployed signer builds its metadata as `${SIGNET_INFO_PREFIX}:${version_id}`.
  // We pass the already-joined INFO bytes so the interop tool signs exactly what
  // the service would for this (prefix, version_id).
  const signed = JSON.parse(
    rust('sign', {
      env: { PKCS8: pkcs8, INFO: `${prefix}:${signKey}` },
      input: JSON.stringify({ blinded_message: b64(blindedMsg) }),
    })
  );
  const blindSig = fromb64(signed.blind_signature);
  const sig = await SUITE.finalize(pk, prepared, info, blindSig, inv);
  return { sig, prepared, pk };
}

async function main() {
  const { spki, pkcs8 } = JSON.parse(rust('genkey'));

  // Sanity: the modulus must be exactly 2048 bits or TS blind() breaks.
  const pk = await importPub(spki);
  if (pk.algorithm.modulusLength !== 2048) {
    throw new Error(`expected 2048-bit modulus, got ${pk.algorithm.modulusLength}`);
  }

  // 1. Production path: blind under v1, sign under v1, finalize+verify under v1.
  //    Default `freedink-vote` prefix — byte-identical to FreedInk's wire format.
  const { sig, prepared } = await roundTrip({
    spki,
    pkcs8,
    prefix: 'freedink-vote',
    signKey: 'post-v1',
    blindKey: 'post-v1',
  });
  const okV1 = await SUITE.verify(pk, sig, prepared, buildInfo('freedink-vote', 'post-v1'));
  if (!okV1) throw new Error('v1 signature failed TS verification');
  console.log('  [ok] production path: Rust sign -> TS verify (freedink-vote v1)');

  // 2. Cross-version binding: the v1 signature must NOT verify under v2.
  let leaked = false;
  try {
    leaked = await SUITE.verify(pk, sig, prepared, buildInfo('freedink-vote', 'post-v2'));
  } catch {
    leaked = false; // throw == invalid, which is the desired outcome
  }
  if (leaked) throw new Error('SECURITY: v1 token verified under v2 metadata');
  console.log('  [ok] cross-version binding: v1 token rejected under v2');

  // 3. Mismatched sign/blind metadata must also fail to finalize: if the
  //    server signs under v2 but the client blinded under v1, finalize (which
  //    verifies internally) must throw.
  let mismatchRejected = false;
  try {
    await roundTrip({ spki, pkcs8, prefix: 'freedink-vote', signKey: 'post-v2', blindKey: 'post-v1' });
  } catch {
    mismatchRejected = true;
  }
  if (!mismatchRejected) {
    throw new Error('SECURITY: server-side metadata mismatch was accepted');
  }
  console.log('  [ok] metadata mismatch (sign v2 / blind v1) rejected at finalize');

  // 4. Configurable prefix (SIGNET_INFO_PREFIX): a Deforum-style `deforum-ban`
  //    prefix round-trips against the real TS library exactly as freedink-vote
  //    does. This is what unblocks Deforum's remote Signet signer.
  const { sig: banSig, prepared: banPrepared } = await roundTrip({
    spki,
    pkcs8,
    prefix: 'deforum-ban',
    signKey: 'r1',
    blindKey: 'r1',
  });
  const okBan = await SUITE.verify(pk, banSig, banPrepared, buildInfo('deforum-ban', 'r1'));
  if (!okBan) throw new Error('deforum-ban signature failed TS verification');
  console.log('  [ok] configurable prefix: deforum-ban round-trips (Rust sign -> TS verify)');

  // 5. Cross-prefix binding: a deforum-ban token must NOT verify under the
  //    freedink-vote prefix (same key, same action key). Proves the prefix is
  //    bound into the metadata, so the two apps' tokens never cross-validate.
  let crossPrefixLeaked = false;
  try {
    crossPrefixLeaked = await SUITE.verify(pk, banSig, banPrepared, buildInfo('freedink-vote', 'r1'));
  } catch {
    crossPrefixLeaked = false;
  }
  if (crossPrefixLeaked) {
    throw new Error('SECURITY: deforum-ban token verified under freedink-vote prefix');
  }
  console.log('  [ok] cross-prefix binding: deforum-ban token rejected under freedink-vote');

  console.log('INTEROP OK');
}

main().catch((e) => {
  console.error('INTEROP FAILED:', e.message);
  process.exit(1);
});
