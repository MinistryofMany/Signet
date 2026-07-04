// Cross-language VOPRF interop proof (the ADR Phase 2 suite decision gate):
//
//   TS (@cloudflare/voprf-ts + noble) blind
//     -> Rust (voprf crate, via examples/prf_interop_tool — the exact
//        PrfKeys::evaluate path /prf/evaluate runs) blind-evaluate + DLEQ
//     -> TS finalize (verifies the Rust DLEQ proof against the pinned pkS)
//     -> byte-compare against the frozen ecosystem vectors
//        (interop/prf-vectors.json).
//
// Also asserts, adversarially, that a tampered Rust proof and an evaluation
// under a different key are REJECTED by the TS DLEQ verifier, and
// cross-checks the stage-2 disclose HMAC and the pairwise vectors with Node
// crypto. ANY failure exits non-zero; a red run means flip the ciphersuite
// to P256-SHA256 before anything depends on values (see the build-plan ADR).
//
// Usage: node prf.mjs <prf-vectors.json> <path-to-prf_interop_tool>

import {
  Oprf,
  VOPRFClient,
  VOPRFServer,
  Evaluation,
  deriveKeyPair,
} from '@cloudflare/voprf-ts';
import { CryptoNoble } from '@cloudflare/voprf-ts/crypto-noble';
import { hkdfSync, createHmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const [vectorsPath, rustBin] = process.argv.slice(2);
if (!vectorsPath || !rustBin) {
  console.error('usage: node prf.mjs <prf-vectors.json> <path-to-prf_interop_tool>');
  process.exit(2);
}

Oprf.Crypto = CryptoNoble;
const suite = Oprf.Suite.RISTRETTO255_SHA512;
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ` (${detail})` : ''}`);
  if (!ok) failures += 1;
};

const hex = (u8) => Buffer.from(u8).toString('hex');
const b64url = (u8) => Buffer.from(u8).toString('base64url');
// LP(x): 2-byte big-endian length prefix — must mirror src/prf.rs `lp`.
const lp = (x) => {
  const b = Buffer.from(x);
  const len = Buffer.alloc(2);
  len.writeUInt16BE(b.length);
  return Buffer.concat([len, b]);
};

// Key schedule per the ADR / src/prf.rs:
//   seed_null = HKDF-SHA512(ikm=master_seed, salt="", info="minister/v1/nullifier", 32)
//   (skS, pkS) = DeriveKeyPair(seed_null, "minister/v1/nullifier/dedup")   [RFC 9497 §3.2.1]
const masterSeed = Buffer.from(vectors.master_seed_hex, 'hex');
const seedNull = Buffer.from(
  hkdfSync('sha512', masterSeed, Buffer.alloc(0), 'minister/v1/nullifier', 32),
);

// 1. TS DeriveKeyPair must independently reproduce the frozen pkS.
const keyPair = await deriveKeyPair(
  Oprf.Mode.VOPRF,
  suite,
  seedNull,
  Buffer.from('minister/v1/nullifier/dedup'),
);
check(
  'TS DeriveKeyPair reproduces the frozen pkS',
  b64url(keyPair.publicKey) === vectors.public_key_b64url,
  b64url(keyPair.publicKey),
);

// 2. TS blind -> Rust evaluate -> TS finalize (DLEQ verified vs pinned pkS).
const input = Buffer.from(vectors.dedup.input_hex, 'hex');
const client = new VOPRFClient(suite, keyPair.publicKey);
const [finData, evalReq] = await client.blind([input]);
const rustOut = execFileSync(rustBin, [
  vectorsPath,
  hex(evalReq.blinded[0].serialize()),
]).toString();
const rustField = (k) => {
  const m = rustOut.match(new RegExp(`${k}=([0-9a-f]+)`));
  if (!m) throw new Error(`Rust tool output lacks ${k}=`);
  return Buffer.from(m[1], 'hex');
};
check(
  'Rust-derived pkS matches the frozen pkS',
  b64url(rustField('pk')) === vectors.public_key_b64url,
  b64url(rustField('pk')),
);

// voprf-ts Evaluation wire: u16 element count || element || mode byte || proof.
const evalWire = (proofBytes) =>
  Buffer.concat([
    Buffer.from([0, 1]),
    rustField('eval'),
    Buffer.from([Oprf.Mode.VOPRF]),
    proofBytes,
  ]);

let nDedup = null;
try {
  [nDedup] = await client.finalize(
    finData,
    Evaluation.deserialize(suite, evalWire(rustField('proof')), Oprf.Crypto),
  );
  check(
    'TS finalize of the Rust evaluation yields the frozen N_dedup',
    hex(nDedup) === vectors.dedup.n_dedup_hex,
    hex(nDedup),
  );
} catch (e) {
  check('TS finalize (incl. DLEQ verify) of the Rust evaluation', false, e.message);
}

// 3. A tampered Rust DLEQ proof must be REJECTED by the TS verifier.
const tampered = Buffer.from(rustField('proof'));
tampered[5] ^= 0x01;
try {
  await client.finalize(
    finData,
    Evaluation.deserialize(suite, evalWire(tampered), Oprf.Crypto),
  );
  check('tampered Rust proof rejected by TS DLEQ verify', false, 'ACCEPTED');
} catch {
  check('tampered Rust proof rejected by TS DLEQ verify', true);
}

// 4. An evaluation under a DIFFERENT key must fail DLEQ against the pinned pkS.
const otherKeyPair = await deriveKeyPair(
  Oprf.Mode.VOPRF,
  suite,
  Buffer.alloc(32, 0x11),
  Buffer.from('minister/v1/nullifier/dedup'),
);
const otherServer = new VOPRFServer(suite, otherKeyPair.privateKey);
const wrongEval = await otherServer.blindEvaluate(evalReq);
try {
  await client.finalize(finData, wrongEval);
  check('wrong-key evaluation rejected by TS DLEQ verify', false, 'ACCEPTED');
} catch {
  check('wrong-key evaluation rejected by TS DLEQ verify', true);
}

// 5. Stage-2 disclose reproduced in Node crypto over the TS-finalized N_dedup:
//    k_disc = HKDF-SHA512(master_seed, "", "minister/v1/nullifier/disclose" || LP(clientId), 32)
//    N_rp = "mnv1:" + b64url(HMAC-SHA256(k_disc, LP("minister/null/v1")||LP("rp")||LP(N_dedup)||LP(clientId)))
if (nDedup) {
  const clientId = vectors.disclose.client_id;
  const kDisc = Buffer.from(
    hkdfSync(
      'sha512',
      masterSeed,
      Buffer.alloc(0),
      Buffer.concat([Buffer.from('minister/v1/nullifier/disclose'), lp(clientId)]),
      32,
    ),
  );
  const msg = Buffer.concat([
    lp('minister/null/v1'),
    lp('rp'),
    lp(Buffer.from(nDedup)),
    lp(clientId),
  ]);
  const nRp = `mnv1:${createHmac('sha256', kDisc).update(msg).digest('base64url')}`;
  check('Node-derived stage-2 N_rp matches the frozen vector', nRp === vectors.disclose.n_rp, nRp);
}

// 6. Pairwise golden vectors reproduced with Node's createHmac (the exact
//    construction Minister's live path uses).
const pairwiseSecret = Buffer.from(vectors.pairwise.secret_utf8, 'utf8');
for (const v of vectors.pairwise.vectors) {
  const out = createHmac('sha256', pairwiseSecret)
    .update(Buffer.from(v.input, 'utf8'))
    .digest('base64url');
  check(`pairwise vector ${JSON.stringify(v.input)}`, out === v.output, out);
}

if (failures > 0) {
  console.error(`\nPRF INTEROP FAILED: ${failures} check(s) red`);
  process.exit(1);
}
console.log('\nPRF INTEROP OK');
