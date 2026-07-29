/**
 * Direct tests for the deliberately-broken predecessors.
 *
 * The point of these is not that the naive scheme fails — it does not, when
 * everyone is honest, and that is exactly why it shipped. These tests pin down that
 * it produces genuinely valid BIP-340 signatures (so the attack exhibits are
 * attacking a working scheme, not a strawman), and that its aggregation really is
 * the plain reversible sum the attacks depend on.
 */
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  G,
  INFINITY,
  N,
  add,
  bytesToHex,
  cbytes,
  mul,
  negate,
  randomScalar,
  utf8,
  xbytes,
} from './field.js';
import { nobleVerify, verify } from './bip340.js';
import { keyAgg } from './keyagg.js';
import { naiveKeyAgg, naiveNonceAgg, naiveSign, sumPoints } from './naive.js';

const MSG = sha256(utf8('the honest case, which is the whole problem'));

describe('sumPoints', () => {
  it('is plain addition, and therefore reversible', () => {
    const a = mul(G, randomScalar());
    const b = mul(G, randomScalar());
    const target = mul(G, randomScalar());
    // The one line every attack in this lab is built on: solve for the last term.
    const last = add(target, negate(add(a, b)));
    expect(sumPoints([a, b, last], 'aggregate nonce').equals(target)).toBe(true);
  });

  it('fails closed when the sum cancels to infinity', () => {
    const a = mul(G, randomScalar());
    expect(() => sumPoints([a, negate(a)], 'aggregate key')).toThrow(/infinity/);
    expect(() => sumPoints([INFINITY], 'aggregate nonce')).toThrow(/infinity/);
  });

  it('names what cancelled, so the failure is attributable', () => {
    const a = mul(G, randomScalar());
    expect(() => sumPoints([a, negate(a)], 'aggregate nonce')).toThrow(/aggregate nonce/);
  });
});

describe('naive aggregation', () => {
  it('naiveKeyAgg is Σ P_i with no coefficients at all', () => {
    const secrets = [randomScalar(), randomScalar(), randomScalar()];
    const keys = secrets.map((d) => cbytes(mul(G, d)));
    const sum = secrets.reduce((acc, d) => acc + d, 0n);
    expect(naiveKeyAgg(keys).equals(mul(G, sum))).toBe(true);
  });

  it('differs from BIP-327 aggregation for the same keys', () => {
    const keys = [1, 2, 3].map(() => cbytes(mul(G, randomScalar())));
    expect(bytesToHex(xbytes(naiveKeyAgg(keys)))).not.toBe(
      bytesToHex(xbytes(keyAgg(keys).Q)),
    );
  });

  it('naiveNonceAgg is Σ R_i, with no b coefficient in sight', () => {
    const ks = [randomScalar(), randomScalar()];
    const pts = ks.map((k) => mul(G, k));
    expect(naiveNonceAgg(pts).equals(mul(G, ks[0] + ks[1]))).toBe(true);
  });

  it('rejects a malformed key rather than aggregating garbage', () => {
    const good = cbytes(mul(G, randomScalar()));
    const bad = good.slice();
    bad[0] = 4;
    expect(() => naiveKeyAgg([good, bad])).toThrow();
  });
});

describe('the naive protocol on honest inputs', () => {
  for (const n of [2, 3, 5]) {
    it(`${n} honest signers produce a signature a real BIP-340 verifier accepts`, () => {
      const signers = Array.from({ length: n }, () => ({ d: randomScalar(), k: randomScalar() }));
      const r = naiveSign(signers, MSG);
      expect(r.signature).toHaveLength(64);
      expect(verify(r.signature, MSG, r.aggregateKeyX).valid).toBe(true);
      expect(nobleVerify(r.signature, MSG, r.aggregateKeyX)).toBe(true);
      expect(r.partials).toHaveLength(n);
    });
  }

  it('Σ s_i is the s in the signature', () => {
    const signers = [1, 2, 3].map(() => ({ d: randomScalar(), k: randomScalar() }));
    const r = naiveSign(signers, MSG);
    const summed = r.partials.reduce((acc, s) => (acc + s) % N, 0n);
    expect(r.s).toBe(summed);
  });

  it('commits to Σ R_i and Σ P_i — the aggregates an attacker can steer', () => {
    const signers = [1, 2].map(() => ({ d: randomScalar(), k: randomScalar() }));
    const r = naiveSign(signers, MSG);
    expect(bytesToHex(r.signature.subarray(0, 32))).toBe(bytesToHex(xbytes(r.R)));
    expect(r.Q.equals(naiveKeyAgg(signers.map((s) => cbytes(mul(G, s.d)))))).toBe(true);
  });

  it('a different message gives a different signature under the same key', () => {
    const signers = [1, 2].map(() => ({ d: randomScalar(), k: randomScalar() }));
    const a = naiveSign(signers, MSG);
    const b = naiveSign(signers, sha256(utf8('something else entirely')));
    expect(bytesToHex(a.aggregateKeyX)).toBe(bytesToHex(b.aggregateKeyX));
    expect(bytesToHex(a.signature)).not.toBe(bytesToHex(b.signature));
  });
});
