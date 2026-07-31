/**
 * How much work each exhibit actually does, asserted exactly.
 *
 * A wall-clock ceiling is the obvious guard and the wrong one: CI runners vary by
 * more than the regression you are trying to catch, so the threshold has to be set
 * so loose that it catches nothing. Counting scalar multiplications instead is
 * deterministic, identical on every machine, and *more* sensitive — the bug this
 * file exists to prevent showed up as exactly 2x the necessary calls.
 *
 * Every module reaches the curve through `mul` in field.ts, so mocking that one
 * function counts the whole program. Noble's own internals are not counted: a call
 * into `schnorr.verify` is one opaque unit here, which is fine, because what these
 * tests watch for is *our* code doing something twice.
 *
 * When one of these numbers changes, that is the point. Update it deliberately and
 * say why in the commit — an expected count that drifts silently is worse than no
 * count at all.
 */
import { describe, expect, it, vi } from 'vitest';

const counter = vi.hoisted(() => ({ mul: 0 }));

vi.mock('./field.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./field.js')>();
  return {
    ...actual,
    mul: (pt: Parameters<typeof actual.mul>[0], k: bigint) => {
      counter.mul++;
      return actual.mul(pt, k);
    },
  };
});

const { makeSigners, runSession } = await import('./session.js');
const { keyAgg } = await import('./keyagg.js');

/** Run something and report the scalar multiplications it cost. */
function cost(fn: () => void): number {
  counter.mul = 0;
  fn();
  return counter.mul;
}

describe('a signing session costs what it should', () => {
  // Linear in the number of signers, which is the property that matters. Roughly:
  //   u      key-aggregation contributions        a_i·P_i
  //   2u     nonce generation                     two points per signer
  //   6u     signing                              the signer's key, its two nonce
  //                                               points, and the mandated self-check
  //   3u     the aggregator's partial verification
  //   3u     the two sides of the equation, for display
  //   u + 3  one session derivation, plus the final verification
  //
  // The exact total is pinned rather than derived — the point of the number is that
  // it does not move without someone deciding it should. The SHAPE is the real
  // assertion: 17 per signer and a small constant. It was 4u² + 22u + 5 until the
  // session values stopped being re-derived per signer, which is what a linear
  // expectation here now prevents from coming back.
  const expected = (u: number): number => 17 * u + 4;

  for (const u of [2, 3, 5]) {
    it(`${u} signers: ${expected(u)} scalar multiplications, no more`, () => {
      const signers = makeSigners(u);
      const spent = cost(() => {
        runSession(signers, 'Move 2 BTC to the cold wallet', { sortKeys: true });
      });
      expect(spent).toBe(expected(u));
    });
  }

  it('scales linearly — a fixed cost plus a per-signer one, with nothing quadratic', () => {
    const at = (u: number): number =>
      cost(() => {
        runSession(makeSigners(u), 'Move 2 BTC to the cold wallet', { sortKeys: true });
      });
    const [two, three, five] = [at(2), at(3), at(5)];
    // Equal successive differences per signer is what rules out an O(u²) loop
    // creeping in — the shape of the growth, not just its size.
    expect(three - two).toBe(17);
    expect((five - three) / 2).toBe(17);
  });

  it('tampering with a partial costs nothing extra', () => {
    // The tamper path recomputes against the corrupted scalar. If it recomputed
    // *in addition to* an earlier value rather than instead of it, this would rise —
    // which is precisely the regression that prompted this file.
    const signers = makeSigners(3);
    const clean = cost(() => runSession(signers, 'x', { sortKeys: true }));
    const tampered = cost(() => runSession(signers, 'x', { sortKeys: true, tamperIndex: 1 }));
    expect(tampered).toBe(clean);
  });
});

describe('key aggregation costs what it should', () => {
  it('is one scalar multiplication per key and not one more', () => {
    const keys = makeSigners(4).map((s) => s.pubkey);
    expect(cost(() => void keyAgg(keys))).toBe(4);
  });

  it('does not recompute when the same key list is aggregated again', () => {
    const keys = makeSigners(3).map((s) => s.pubkey);
    const once = cost(() => void keyAgg(keys));
    const twice = cost(() => {
      keyAgg(keys);
      keyAgg(keys);
    });
    // No cache is claimed, so this documents the honest answer: it costs twice.
    // Here to catch the opposite mistake — a cache appearing without a test.
    expect(twice).toBe(once * 2);
  });
});
