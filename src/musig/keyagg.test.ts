import { describe, expect, it } from 'vitest';
import {
  G,
  N,
  add,
  bigTo32,
  bytesToHex,
  cbytes,
  cpoint,
  hexToBytes,
  mod,
  mul,
  randomScalar,
  xbytes,
} from './field.js';
import {
  InvalidContributionError,
  applyTweak,
  getSecondKey,
  getXonlyPk,
  hashKeys,
  keyAgg,
  keyAggAndTweak,
  keyAggCoeff,
  keyAggWithTrace,
  sessionKeyAggCoeff,
} from './keyagg.js';

const keysFor = (count: number) =>
  Array.from({ length: count }, () => cbytes(mul(G, randomScalar())));

describe('key-aggregation coefficients', () => {
  it('computes Q = Σ a_i·P_i — the definition, checked in the group', () => {
    const keys = keysFor(4);
    const { ctx } = keyAggWithTrace(keys);
    let expected = mul(G, 0n);
    for (const pk of keys) expected = add(expected, mul(cpoint(pk), keyAggCoeff(keys, pk)));
    expect(ctx.Q.equals(expected)).toBe(true);
  });

  it('gives coefficient 1 to exactly one key — the second key', () => {
    const keys = keysFor(4);
    const { trace } = keyAggWithTrace(keys);
    const ones = trace.rows.filter((r) => r.coeff === 1n);
    expect(ones).toHaveLength(1);
    expect(ones[0].isSecondKey).toBe(true);
    expect(ones[0].pubkey).toBe(bytesToHex(getSecondKey(keys)));
    expect(ones[0].pubkey).toBe(bytesToHex(keys[1]));
  });

  it('uses 33 zero bytes as the second key when every key is identical', () => {
    const pk = cbytes(mul(G, randomScalar()));
    const keys = [pk, pk, pk];
    expect(bytesToHex(getSecondKey(keys))).toBe('00'.repeat(33));
    // No key equals the all-zero sentinel, so every coefficient is hash-derived.
    const { trace } = keyAggWithTrace(keys);
    expect(trace.rows.every((r) => r.coeff !== 1n)).toBe(true);
    expect(trace.rows.every((r) => !r.isSecondKey)).toBe(true);
  });

  it('binds each coefficient to the WHOLE key list — this is the rogue-key defence', () => {
    const [a, b, c] = keysFor(3);
    const coeffAB = keyAggCoeff([a, b], a);
    const coeffABC = keyAggCoeff([a, b, c], a);
    expect(coeffAB).not.toBe(coeffABC);
    // and L itself changes with the list
    expect(bytesToHex(hashKeys([a, b]))).not.toBe(bytesToHex(hashKeys([a, b, c])));
  });

  it('is order-dependent, which is why KeySort exists', () => {
    const [a, b, c] = keysFor(3);
    expect(bytesToHex(getXonlyPk(keyAgg([a, b, c])))).not.toBe(
      bytesToHex(getXonlyPk(keyAgg([c, b, a]))),
    );
  });

  it('is deterministic — the same list always gives the same aggregate key', () => {
    const keys = keysFor(3);
    expect(bytesToHex(getXonlyPk(keyAgg(keys)))).toBe(bytesToHex(getXonlyPk(keyAgg(keys))));
  });

  it('rejects a malformed key and names the offending signer index', () => {
    const keys = keysFor(3);
    // "Public key exceeds field size" — the spec's own malformed-key shape.
    keys[1] = hexToBytes('02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30');
    try {
      keyAgg(keys);
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidContributionError);
      expect((err as InvalidContributionError).signer).toBe(1);
      expect((err as InvalidContributionError).contrib).toBe('pubkey');
    }
  });

  it('rejects an empty key list', () => {
    expect(() => keyAgg([])).toThrow(/empty/);
  });

  it('reports the aggregate key both x-only and compressed', () => {
    const { ctx, trace } = keyAggWithTrace(keysFor(2));
    expect(trace.aggregateX).toBe(bytesToHex(xbytes(ctx.Q)));
    expect(trace.aggregateCompressed).toBe(bytesToHex(cbytes(ctx.Q)));
    expect(trace.aggregateCompressed.slice(0, 2)).toBe(trace.qHasEvenY ? '02' : '03');
  });
});

describe('sessionKeyAggCoeff', () => {
  it('refuses a signer who is not in the key list', () => {
    const keys = keysFor(2);
    const stranger = mul(G, randomScalar());
    expect(() => sessionKeyAggCoeff(keys, stranger)).toThrow(/must be included/);
  });

  it('agrees with keyAggCoeff for a listed signer', () => {
    const d = randomScalar();
    const keys = [cbytes(mul(G, d)), ...keysFor(2)];
    expect(sessionKeyAggCoeff(keys, mul(G, d))).toBe(keyAggCoeff(keys, keys[0]));
  });
});

describe('tweaking (spec coverage; not a UI exhibit)', () => {
  it('plain tweaking adds t·G and accumulates tacc', () => {
    const keys = keysFor(2);
    const base = keyAgg(keys);
    const t = randomScalar();
    const tweaked = applyTweak(base, bigTo32(t), false);
    expect(tweaked.Q.equals(add(base.Q, mul(G, t)))).toBe(true);
    expect(tweaked.gacc).toBe(1n);
    expect(tweaked.tacc).toBe(mod(t, N));
  });

  it('x-only tweaking negates an odd-y Q first and records it in gacc', () => {
    // Search for a key set whose aggregate has odd y so the negation branch runs.
    let keys = keysFor(2);
    let base = keyAgg(keys);
    for (let i = 0; i < 50 && evenY(base.Q); i++) {
      keys = keysFor(2);
      base = keyAgg(keys);
    }
    expect(evenY(base.Q)).toBe(false);
    const tweaked = applyTweak(base, bigTo32(1n), true);
    expect(tweaked.gacc).toBe(N - 1n);
    expect(tweaked.Q.equals(add(base.Q.negate(), G))).toBe(true);
  });

  it('rejects an out-of-range tweak, a wrong-length tweak, and an infinite result', () => {
    const keys = keysFor(2);
    const base = keyAgg(keys);
    expect(() => applyTweak(base, bigTo32(N), false)).toThrow(/less than n/);
    expect(() => applyTweak(base, new Uint8Array(31), false)).toThrow(/32-byte/);
    // Choose t so that Q + t·G = infinity: t·G = −Q is not directly solvable, but
    // a single-key group with a known secret makes it easy.
    const d = randomScalar();
    const single = keyAgg([cbytes(mul(G, d))]);
    const a = keyAggCoeff([cbytes(mul(G, d))], cbytes(mul(G, d)));
    const t = mod(N - mod(a * d, N), N);
    expect(() => applyTweak(single, bigTo32(t), false)).toThrow(/infinity/);
  });

  it('requires tweaks and isXonly to be the same length', () => {
    expect(() => keyAggAndTweak(keysFor(2), [bigTo32(1n)], [])).toThrow(/same length/);
  });
});

function evenY(pt: ReturnType<typeof mul>): boolean {
  return mod(pt.y, 2n) === 0n;
}
