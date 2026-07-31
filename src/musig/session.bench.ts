/**
 * The protocol on its own, with no DOM anywhere near it — the "Node (no DOM)" row of
 * the README's performance table, and the number that isolates the cryptography from
 * the rendering.
 *
 * Run with `npm run bench`. Not part of `npm test`: benchmarks are noisy by nature
 * and a slow laptop should never fail the suite.
 *
 * Signers are generated once, outside the timed body, so this measures the protocol
 * rather than key generation. `runSession` itself caches nothing between calls — key
 * aggregation, both nonce rounds, every partial signature, every partial
 * verification and two independent full verifications all happen every time — which
 * is what the page pays when you press "New keys".
 */
import { bench, describe } from 'vitest';
import { loneSignerComparison, makeSigners, runSession } from './session.js';

const MESSAGE = 'Move 2 BTC to the cold wallet';
const signerSets = new Map([2, 3, 5].map((n) => [n, makeSigners(n)]));

describe('a full MuSig2 session, no DOM', () => {
  for (const count of [2, 3, 5]) {
    bench(`${count} signers — aggregate, sign both rounds, verify twice`, () => {
      runSession(signerSets.get(count)!, MESSAGE, { sortKeys: true });
    });
  }
});

describe('the headline claim', () => {
  const result = runSession(signerSets.get(3)!, MESSAGE, { sortKeys: true });
  bench('lone-signer comparison — group signature against a single-signer one', () => {
    loneSignerComparison(result);
  });
});
