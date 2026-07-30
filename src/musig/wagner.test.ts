/**
 * Tests for the Wagner k-list forgery.
 *
 * The load-bearing assertions here are unusual: this suite must prove that an
 * attack SUCCEEDS. A demo that claims to forge a signature and quietly doesn't is
 * worse than no demo, so the forgery is checked against the same verifier the honest
 * path uses, and the surrounding conditions (honest signer never saw the message, no
 * nonce reused, key aggregation sound) are checked too — otherwise a "forgery" could
 * be an artefact of something else being broken.
 */
import { describe, expect, it } from 'vitest';
import { G, N, add, mod, mul, randomScalar, utf8 } from './field.js';
import {
  attemptTwoNonceForgery,
  forgeSingleNonce,
  fullWidthCost,
  toyKeyAggCoeffs,
  toyNonceCoeff,
  truncChallenge,
  verifyToy,
  wagnerFourSum,
} from './wagner.js';

const TIMEOUT = 60_000;

describe('the truncated challenge', () => {
  it('is the real hash, cut to the stated width and nothing else', () => {
    const R = mul(G, 3n);
    const Q = mul(G, 5n);
    const msg = utf8('m');
    const wide = truncChallenge(64, R, Q, msg);
    const narrow = truncChallenge(24, R, Q, msg);
    expect(narrow).toBe(wide & ((1n << 24n) - 1n));
    expect(narrow < 1n << 24n).toBe(true);
  });

  it('changes with the nonce, the key, and the message', () => {
    const msg = utf8('m');
    const base = truncChallenge(30, mul(G, 3n), mul(G, 5n), msg);
    expect(truncChallenge(30, mul(G, 4n), mul(G, 5n), msg)).not.toBe(base);
    expect(truncChallenge(30, mul(G, 3n), mul(G, 6n), msg)).not.toBe(base);
    expect(truncChallenge(30, mul(G, 3n), mul(G, 5n), utf8('n'))).not.toBe(base);
  });
});

describe('the toy scheme itself is sound apart from the nonce flaw', () => {
  it('key-aggregation coefficients are hash-derived and distinct per key', () => {
    const keys = [mul(G, randomScalar()), mul(G, randomScalar()), mul(G, randomScalar())];
    const coeffs = toyKeyAggCoeffs(keys);
    expect(coeffs).toHaveLength(3);
    expect(new Set(coeffs.map(String)).size).toBe(3);
    expect(coeffs.every((c) => c > 1n && c < N)).toBe(true);
    // Binds the whole key list: drop a key and every coefficient moves.
    const fewer = toyKeyAggCoeffs(keys.slice(0, 2));
    expect(fewer[0]).not.toBe(coeffs[0]);
  });

  it('the nonce coefficient depends on both nonce halves', () => {
    const Q = mul(G, randomScalar());
    const msg = utf8('m');
    const R1 = mul(G, 7n);
    const R2 = mul(G, 9n);
    const base = toyNonceCoeff(R1, R2, Q, msg);
    expect(toyNonceCoeff(mul(G, 8n), R2, Q, msg)).not.toBe(base);
    expect(toyNonceCoeff(R1, mul(G, 10n), Q, msg)).not.toBe(base);
  });

  it('the verifier accepts an honest signature and rejects a tampered one', () => {
    const d = randomScalar();
    const Q = mul(G, d);
    const msg = utf8('an honest message');
    const k = randomScalar();
    const R = mul(G, k);
    const e = truncChallenge(27, R, Q, msg);
    const s = mod(k + e * d, N);
    expect(verifyToy(27, R, s, Q, msg)).toBe(true);
    expect(verifyToy(27, R, mod(s + 1n, N), Q, msg)).toBe(false);
    expect(verifyToy(27, R, s, Q, utf8('a different message'))).toBe(false);
  });
});

describe("Wagner's k-tree", () => {
  it('finds a four-way sum that hits the target EXACTLY, not just modulo 2^bits', () => {
    // The k-tree is probabilistic: it finds solutions that happen to satisfy its
    // intermediate low-bit constraints, so it is given lists big enough for such a
    // solution to exist rather than a planted one it has no reason to reach.
    const bits = 20;
    const mask = (1n << BigInt(bits)) - 1n;
    let seed = 123456789n;
    const nextValue = (): bigint => {
      seed = (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
      return (seed >> 20n) & mask;
    };
    const lists = Array.from({ length: 4 }, () =>
      Array.from({ length: 1024 }, (_, i) => ({ e: nextValue(), rho: BigInt(i) })),
    );
    const target = 0x5a5a5n;

    const found = wagnerFourSum(lists, target, bits);
    expect(found).not.toBeNull();
    expect(found!.candidatesExact).toBeGreaterThan(0);

    // Soundness is the assertion that matters: whatever comes back must be a real
    // solution over the integers, because the algebra downstream needs equality of
    // scalars and a mod-2^bits match would silently produce an invalid signature.
    const sum = found!.rhos.reduce(
      (acc, rho, j) => acc + lists[j].find((x) => x.rho === rho)!.e,
      0n,
    );
    expect(sum).toBe(target);
  });

  it('returns null rather than an inexact answer when no exact solution can exist', () => {
    // Values are all under 2^8, so no four of them can sum to 2^19 — every modular
    // match must be discarded by the exactness filter.
    const lists = Array.from({ length: 4 }, () =>
      Array.from({ length: 512 }, (_, i) => ({ e: BigInt(i % 256), rho: BigInt(i) })),
    );
    expect(wagnerFourSum(lists, 1n << 19n, 20)).toBeNull();
  });

  it('refuses a list count it was not written for', () => {
    expect(() => wagnerFourSum([[], [], []], 0n, 20)).toThrow(/exactly 4 lists/);
  });
});

describe('the single-nonce forgery — this attack must SUCCEED', () => {
  it(
    'produces a signature the real verifier accepts on a message nobody authorised',
    () => {
      const r = forgeSingleNonce();

      // The forgery is real: the same verifier that accepts honest signatures.
      expect(r.verified).toBe(true);
      // And it is genuinely a forgery, not a replay of something that was signed.
      expect(r.honestSignerNeverSawIt).toBe(true);
      expect(r.queriedMessages).toHaveLength(r.sessions);
      expect(r.queriedMessages).not.toContain(r.forgedMessage);
      // The algebra required exact equality of scalars, not merely low bits.
      expect(r.exactSum).toBe(true);
      expect(r.sumOfChallenges).toBe(r.eStar);
      expect(r.sessionDetail).toHaveLength(r.sessions);
      expect(r.forgedR).toHaveLength(64);
      expect(r.forgedS).toHaveLength(64);
    },
    TIMEOUT,
  );

  it(
    'succeeds repeatedly, so the demo is not relying on a lucky run',
    () => {
      for (let i = 0; i < 3; i++) {
        const r = forgeSingleNonce();
        expect(r.verified).toBe(true);
        expect(r.sumOfChallenges).toBe(r.eStar);
      }
    },
    TIMEOUT,
  );

  it(
    'each session challenge really is the challenge for the nonce it published',
    () => {
      const r = forgeSingleNonce();
      // Σ e_j = e* is the whole point, and each e_j must be a real challenge value.
      const sum = r.sessionDetail.reduce((acc, s) => acc + s.e, 0n);
      expect(sum).toBe(r.eStar);
      expect(r.sessionDetail.every((s) => s.e < 1n << BigInt(r.bits))).toBe(true);
      // Every session used a distinct adversary offset found by the search.
      expect(new Set(r.sessionDetail.map((s) => String(s.rho))).size).toBe(r.sessions);
    },
    TIMEOUT,
  );

  it(
    'works at other challenge widths too',
    () => {
      for (const [bits, listBits] of [
        [24, 10],
        [27, 11],
      ] as const) {
        const r = forgeSingleNonce({ bits, listBits });
        expect(r.verified).toBe(true);
        expect(r.bits).toBe(bits);
      }
    },
    TIMEOUT,
  );

  it('is honest about what the same attack costs unreduced', () => {
    expect(fullWidthCost(4)).toMatch(/2\^85/);
    expect(fullWidthCost(4)).toMatch(/break in theory/);
    expect(fullWidthCost(16)).toMatch(/2\^51/);
  });
});

describe('the same attack against two nonces — this attack must FAIL', () => {
  it(
    'cannot fix a target: every candidate nonce assignment gives a different e*',
    () => {
      const r = attemptTwoNonceForgery();
      expect(r.targetDrifted).toBe(true);
      expect(r.distinctTargets).toBe(r.probes.length);
      expect(r.probes.length).toBeGreaterThanOrEqual(2);
      // Every probe's nonce coefficients differ too — that is what moves the target.
      const bSets = r.probes.map((p) => p.bs.join(','));
      expect(new Set(bSets).size).toBe(r.probes.length);
    },
    TIMEOUT,
  );

  it(
    'the completed attempt is rejected by the same verifier that accepted the forgery',
    () => {
      for (let i = 0; i < 3; i++) {
        const r = attemptTwoNonceForgery();
        expect(r.verified).toBe(false);
        expect(r.targetedEStar).not.toBe(r.actualEStar);
      }
    },
    TIMEOUT,
  );

  it('explains the failure in terms of the missing precondition', () => {
    const r = attemptTwoNonceForgery();
    expect(r.explanation).toMatch(/k-tree needs to know what sum/);
    expect(r.explanation).toMatch(/b_j/);
  });
});

describe('the two demonstrations are directly comparable', () => {
  it(
    'same challenge width, same session count — only the nonce count differs',
    () => {
      const broken = forgeSingleNonce({ bits: 24, listBits: 10 });
      const fixed = attemptTwoNonceForgery({ bits: 24 });
      expect(fixed.bits).toBe(broken.bits);
      expect(fixed.sessions).toBe(broken.sessions);
      // The only difference in outcome is the one the second nonce is responsible for.
      expect(broken.verified).toBe(true);
      expect(fixed.verified).toBe(false);
    },
    TIMEOUT,
  );

  it('the honest signer in the broken scheme never reuses a nonce', () => {
    // Nonce reuse would leak the key and forge trivially — a different attack. If the
    // signer ever reused one, `respond` would throw and this would fail.
    const r = forgeSingleNonce({ bits: 24, listBits: 10 });
    expect(r.verified).toBe(true);
    expect(new Set(r.sessionDetail.map((s) => s.honestNonceX)).size).toBe(r.sessions);
  });
});

describe('sanity: the toy group operations are the real ones', () => {
  it('point addition and scalar multiplication agree', () => {
    const a = randomScalar();
    const b = randomScalar();
    expect(add(mul(G, a), mul(G, b)).equals(mul(G, mod(a + b, N)))).toBe(true);
  });
});
