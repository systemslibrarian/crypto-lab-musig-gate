/**
 * Tests for the drawable group.
 *
 * The visualisation is only worth anything if the group it draws is real, so these
 * tests check the group axioms and the published constants rather than trusting them:
 * closure, associativity, inverses, the stated order, and that the generator really
 * generates. If any of these failed, the picture would be a lie.
 */
import { describe, expect, it } from 'vitest';
import {
  TOY_N,
  TOY_P,
  type ToyPoint,
  allToyPoints,
  isOnCurve,
  randomToyPoints,
  toyAdd,
  toyAggregate,
  toyEquals,
  toyGenerator,
  toyMul,
  toyNegate,
  toyOrder,
} from './toycurve.js';

describe('the toy group is a real elliptic curve group', () => {
  const points = allToyPoints();

  it('has the stated size: 126 affine points plus infinity = 127', () => {
    expect(points).toHaveLength(126);
    expect(points.length + 1).toBe(Number(TOY_N));
    expect(TOY_P).toBe(127n);
  });

  it('every listed point satisfies y² = x³ + 7 over F_127', () => {
    expect(points.every((p) => isOnCurve(p))).toBe(true);
    // And nothing off the curve slips through the check.
    expect(isOnCurve({ x: 1n, y: 1n })).toBe(false);
    expect(isOnCurve(null)).toBe(true);
  });

  it('is closed under addition', () => {
    for (let i = 0; i < points.length; i += 7) {
      for (let j = 0; j < points.length; j += 11) {
        const sum = toyAdd(points[i], points[j]);
        expect(isOnCurve(sum)).toBe(true);
      }
    }
  });

  it('is commutative and associative', () => {
    const [a, b, c] = [points[3], points[17], points[41]];
    expect(toyEquals(toyAdd(a, b), toyAdd(b, a))).toBe(true);
    expect(toyEquals(toyAdd(toyAdd(a, b), c), toyAdd(a, toyAdd(b, c)))).toBe(true);
  });

  it('infinity is the identity, and every point has an inverse', () => {
    for (let i = 0; i < points.length; i += 5) {
      const p: ToyPoint = points[i];
      expect(toyEquals(toyAdd(p, null), p)).toBe(true);
      expect(toyAdd(p, toyNegate(p))).toBeNull();
      expect(isOnCurve(toyNegate(p))).toBe(true);
    }
  });

  it('doubling agrees with adding a point to itself', () => {
    for (let i = 0; i < points.length; i += 9) {
      expect(toyEquals(toyMul(points[i], 2n), toyAdd(points[i], points[i]))).toBe(true);
    }
  });

  it('scalar multiplication is a homomorphism: (j+k)·P = j·P + k·P', () => {
    const P = points[13];
    for (const [j, k] of [
      [3n, 5n],
      [40n, 61n],
      [126n, 1n],
    ] as const) {
      expect(toyEquals(toyMul(P, j + k), toyAdd(toyMul(P, j), toyMul(P, k)))).toBe(true);
    }
  });

  it('the group order is 127, and n·P is infinity for every point', () => {
    for (let i = 0; i < points.length; i += 5) {
      expect(toyMul(points[i], TOY_N)).toBeNull();
    }
  });

  it('the order is prime, so every non-identity point generates the whole group', () => {
    for (let i = 0; i < points.length; i += 17) {
      expect(toyOrder(points[i])).toBe(TOY_N);
    }
    expect(toyOrder(null)).toBe(1n);
  });

  it('the generator enumerates all 127 group elements', () => {
    const g = toyGenerator();
    const seen = new Set<string>();
    let acc: ToyPoint = null;
    for (let k = 0n; k < TOY_N; k++) {
      seen.add(acc === null ? 'inf' : `${acc.x},${acc.y}`);
      acc = toyAdd(acc, g);
    }
    expect(seen.size).toBe(Number(TOY_N));
    expect(acc).toBeNull(); // wrapped exactly back to the identity
  });

  it('scalar multiples land somewhere unrelated-looking — no visual pattern to read', () => {
    const g = toyGenerator();
    const xs = [1n, 2n, 3n, 4n, 5n].map((k) => toyMul(g, k)).map((p) => (p as { x: bigint }).x);
    // Consecutive multiples are not monotone in x; that is the point of the picture.
    const monotone = xs.every((x, i) => i === 0 || x > xs[i - 1]);
    expect(monotone).toBe(false);
  });
});

describe('key aggregation on the drawable group', () => {
  it('records every intermediate point so the accumulation can be drawn', () => {
    const pts = allToyPoints().slice(0, 3);
    const agg = toyAggregate(pts);
    expect(agg.rows).toHaveLength(3);
    expect(agg.naivePath).toHaveLength(3);
    expect(agg.allPoints).toHaveLength(126);
    // The running total really is the running total.
    let running: ToyPoint = null;
    for (const row of agg.rows) {
      running = toyAdd(running, row.weighted);
      expect(toyEquals(row.runningTotal, running)).toBe(true);
    }
    expect(toyEquals(agg.aggregate, running)).toBe(true);
  });

  it('every drawn point is on the curve', () => {
    const agg = toyAggregate(allToyPoints().slice(10, 14));
    expect(isOnCurve(agg.aggregate)).toBe(true);
    expect(isOnCurve(agg.naiveAggregate)).toBe(true);
    expect(agg.rows.every((r) => isOnCurve(r.weighted) && isOnCurve(r.runningTotal))).toBe(true);
    expect(agg.naivePath.every((p) => isOnCurve(p))).toBe(true);
  });

  it('weighted and naive aggregates land in different places', () => {
    // The lesson of the picture: coefficients move the result somewhere else.
    let differing = 0;
    const all = allToyPoints();
    for (let i = 0; i + 3 < all.length; i += 13) {
      const agg = toyAggregate(all.slice(i, i + 3));
      if (!toyEquals(agg.aggregate, agg.naiveAggregate)) differing++;
    }
    expect(differing).toBeGreaterThan(5);
  });

  it('coefficients stay in [1, n-1] so no key is ever erased', () => {
    const agg = toyAggregate(allToyPoints().slice(0, 6));
    expect(agg.rows.every((r) => r.coeff >= 1n && r.coeff < TOY_N)).toBe(true);
  });

  it('coefficients are bound to the whole key list', () => {
    const all = allToyPoints();
    const two = toyAggregate(all.slice(0, 2));
    const three = toyAggregate(all.slice(0, 3));
    // Same first key, different list ⇒ different coefficient.
    expect(two.rows[0].coeff).not.toBe(three.rows[0].coeff);
  });

  it('is order-dependent, like the real construction', () => {
    const [a, b, c] = allToyPoints().slice(0, 3);
    const forward = toyAggregate([a, b, c]).aggregate;
    const reversed = toyAggregate([c, b, a]).aggregate;
    expect(toyEquals(forward, reversed)).toBe(false);
  });

  it('is deterministic for the same list', () => {
    const pts = allToyPoints().slice(4, 8);
    expect(toyEquals(toyAggregate(pts).aggregate, toyAggregate(pts).aggregate)).toBe(true);
  });
});

describe('randomToyPoints', () => {
  it('returns the requested number of distinct on-curve points', () => {
    for (const n of [1, 3, 5]) {
      const pts = randomToyPoints(n);
      expect(pts).toHaveLength(n);
      expect(pts.every((p) => isOnCurve(p))).toBe(true);
      expect(new Set(pts.map((p) => `${p.x},${p.y}`)).size).toBe(n);
    }
  });
});
