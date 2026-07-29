/**
 * The BIP-327 known-answer tests. If any of these fail, the implementation is
 * wrong — these bytes come from the specification, not from this code.
 */
import { describe, expect, it } from 'vitest';
import {
  KAT_GROUPS,
  katSummary,
  runAllVectors,
  runDetSignVectors,
  runKeyAggVectors,
  runNonceAggVectors,
  runNonceGenVectors,
  runSigAggVectors,
  runSignVerifyVectors,
  runTweakVectors,
} from './vectors.js';

const GROUPS: [string, () => ReturnType<typeof runKeyAggVectors>][] = [
  ['key aggregation', runKeyAggVectors],
  ['nonce generation', runNonceGenVectors],
  ['nonce aggregation', runNonceAggVectors],
  ['partial signing & verification', runSignVerifyVectors],
  ['tweaked key aggregation', runTweakVectors],
  ['deterministic signing', runDetSignVectors],
  ['signature aggregation', runSigAggVectors],
];

describe('BIP-327 official test vectors', () => {
  for (const [name, run] of GROUPS) {
    describe(name, () => {
      const results = run();

      it('has cases to run', () => {
        expect(results.length).toBeGreaterThan(0);
      });

      for (const r of results) {
        it(`[${r.kind}] ${r.what}`, () => {
          // Surface expected vs actual in the failure message rather than a bare false.
          expect({ pass: r.pass, expected: r.expected, actual: r.actual }).toEqual({
            pass: true,
            expected: r.expected,
            actual: r.actual,
          });
        });
      }
    });
  }

  it('every vector in every group passes', () => {
    const failures = runAllVectors().filter((r) => !r.pass);
    expect(failures).toEqual([]);
  });

  it('covers both accepting and rejecting cases', () => {
    const s = katSummary();
    expect(s.failed).toBe(0);
    expect(s.accept).toBeGreaterThan(0);
    expect(s.reject).toBeGreaterThan(0);
    expect(s.total).toBe(s.accept + s.reject);
  });

  it('describes one group per spec vector file', () => {
    expect(KAT_GROUPS.map((g) => g.id).sort()).toEqual(
      ['det_sign', 'key_agg', 'nonce_agg', 'nonce_gen', 'sig_agg', 'sign_verify', 'tweak'].sort(),
    );
    expect(new Set(runAllVectors().map((r) => r.group))).toEqual(
      new Set(KAT_GROUPS.map((g) => g.id)),
    );
  });
});
