import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  G,
  INFINITY,
  N,
  P,
  add,
  bigTo32,
  bigToLen,
  bytesEqual,
  bytesToBig,
  bytesToHex,
  cbytes,
  cbytesExt,
  concatBytes,
  cpoint,
  cpointExt,
  hasEvenY,
  hexToBytes,
  individualPubkey,
  invN,
  keySort,
  liftX,
  mod,
  mul,
  negate,
  randomScalar,
  taggedHash,
  xbytes,
} from './field.js';

describe('scalar and byte encodings', () => {
  it('round-trips 32-byte big-endian integers', () => {
    for (const x of [0n, 1n, 255n, 256n, N - 1n, (1n << 255n) - 1n]) {
      expect(bytesToBig(bigTo32(x))).toBe(x);
    }
  });

  it('rejects values that do not fit', () => {
    expect(() => bigTo32(1n << 256n)).toThrow();
    expect(() => bigTo32(-1n)).toThrow();
    expect(() => bigToLen(256n, 1)).toThrow();
  });

  it('encodes fixed-width lengths the way the spec does', () => {
    expect(bytesToHex(bigToLen(1n, 1))).toBe('01');
    expect(bytesToHex(bigToLen(38n, 8))).toBe('0000000000000026');
    expect(bytesToHex(bigToLen(0n, 4))).toBe('00000000');
  });

  it('fails closed on malformed hex instead of silently truncating', () => {
    expect(() => hexToBytes('0g')).toThrow(/invalid hex/);
    expect(() => hexToBytes('abc')).toThrow(/odd-length/);
    expect(bytesToHex(hexToBytes('DEADbeef'))).toBe('deadbeef');
  });

  it('mod is the least non-negative residue', () => {
    expect(mod(-1n, 7n)).toBe(6n);
    expect(mod(8n, 7n)).toBe(1n);
    expect(mod(-1n)).toBe(N - 1n);
  });

  it('invN inverts in the scalar field', () => {
    const a = randomScalar();
    expect(mod(a * invN(a), N)).toBe(1n);
  });

  it('randomScalar stays in [1, n-1]', () => {
    for (let i = 0; i < 32; i++) {
      const x = randomScalar();
      expect(x >= 1n && x < N).toBe(true);
    }
  });
});

describe('tagged hashes', () => {
  it('matches SHA256(SHA256(tag) ‖ SHA256(tag) ‖ data)', () => {
    const tag = 'KeyAgg list';
    const th = sha256(new TextEncoder().encode(tag));
    const data = hexToBytes('00112233');
    expect(bytesToHex(taggedHash(tag, data))).toBe(
      bytesToHex(sha256(concatBytes(th, th, data))),
    );
  });

  it('domain-separates: the same data under different tags differs', () => {
    const d = hexToBytes('ff');
    expect(bytesToHex(taggedHash('KeyAgg list', d))).not.toBe(
      bytesToHex(taggedHash('KeyAgg coefficient', d)),
    );
  });
});

describe('point encodings', () => {
  it('lift_x returns the even-y representative', () => {
    const pt = mul(G, randomScalar());
    const lifted = liftX(xbytes(pt));
    expect(lifted).not.toBeNull();
    expect(hasEvenY(lifted!)).toBe(true);
    expect(lifted!.x).toBe(pt.x);
  });

  it('lift_x rejects x ≥ p and non-curve x values', () => {
    expect(liftX(bigTo32(P))).toBeNull();
    // x = 5 is not an x-coordinate on secp256k1 (per the spec's own vector set).
    expect(liftX(bigTo32(5n))).toBeNull();
  });

  it('cbytes/cpoint round-trip and preserve the y parity', () => {
    for (let i = 0; i < 8; i++) {
      const pt = mul(G, randomScalar());
      const c = cbytes(pt);
      expect(c.length).toBe(33);
      expect(c[0]).toBe(hasEvenY(pt) ? 2 : 3);
      expect(cpoint(c).equals(pt)).toBe(true);
      expect(cpoint(cbytes(negate(pt))).equals(negate(pt))).toBe(true);
    }
  });

  it('cpoint rejects a bad prefix, a bad length, and an off-curve x', () => {
    const good = cbytes(mul(G, 7n));
    const badPrefix = concatBytes(new Uint8Array([4]), good.subarray(1));
    expect(() => cpoint(badPrefix)).toThrow(/prefix/);
    expect(() => cpoint(good.subarray(0, 32))).toThrow(/length/);
    expect(() => cpoint(concatBytes(new Uint8Array([2]), bigTo32(5n)))).toThrow(/curve/);
  });

  it('the extended codec maps infinity to 33 zero bytes and back', () => {
    expect(bytesToHex(cbytesExt(INFINITY))).toBe('00'.repeat(33));
    expect(cpointExt(new Uint8Array(33)).is0()).toBe(true);
    expect(() => cbytes(INFINITY)).toThrow();
    expect(() => xbytes(INFINITY)).toThrow();
  });

  it('mul tolerates the scalar zero and add tolerates infinity', () => {
    expect(mul(G, 0n).is0()).toBe(true);
    expect(add(INFINITY, G).equals(G)).toBe(true);
    expect(add(G, negate(G)).is0()).toBe(true);
    expect(mul(INFINITY, 5n).is0()).toBe(true);
  });

  it('individualPubkey rejects out-of-range secret keys', () => {
    expect(() => individualPubkey(bigTo32(0n))).toThrow();
    expect(() => individualPubkey(bigTo32(N))).toThrow();
    expect(individualPubkey(bigTo32(1n))).toHaveLength(33);
  });
});

describe('KeySort', () => {
  it('sorts lexicographically on the 33-byte encoding and does not mutate the input', () => {
    const keys = [3n, 1n, 2n, 9n].map((d) => cbytes(mul(G, d)));
    const original = keys.map(bytesToHex);
    const sorted = keySort(keys).map(bytesToHex);
    expect(keys.map(bytesToHex)).toEqual(original); // input untouched
    expect(sorted).toEqual([...sorted].sort());
    expect(new Set(sorted)).toEqual(new Set(original));
  });

  it('is idempotent', () => {
    const keys = [5n, 4n, 8n].map((d) => cbytes(mul(G, d)));
    const once = keySort(keys);
    const twice = keySort(once);
    expect(once.every((k, i) => bytesEqual(k, twice[i]))).toBe(true);
  });
});
