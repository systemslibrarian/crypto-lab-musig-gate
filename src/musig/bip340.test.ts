import { describe, expect, it } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { N, P, bigTo32, bytesToHex, hexToBytes, utf8 } from './field.js';
import { challenge, nobleVerify, scalarHex, verify } from './bip340.js';

const MSG = sha256(utf8('one signature, one key'));

function freshSignature(): { sig: Uint8Array; pk: Uint8Array } {
  const sk = schnorr.utils.randomSecretKey();
  return { sig: schnorr.sign(MSG, sk), pk: schnorr.getPublicKey(sk) };
}

describe('the hand-rolled BIP-340 verifier', () => {
  it('accepts genuine signatures produced by @noble/curves', () => {
    for (let i = 0; i < 16; i++) {
      const { sig, pk } = freshSignature();
      const r = verify(sig, MSG, pk);
      expect(r.valid).toBe(true);
      expect(r.nobleValid).toBe(true);
      expect(r.disagreement).toBe(false);
    }
  });

  it('agrees with @noble/curves on randomly corrupted signatures', () => {
    for (let i = 0; i < 64; i++) {
      const { sig, pk } = freshSignature();
      const bad = sig.slice();
      bad[i % 64] ^= 1 << i % 8;
      const r = verify(bad, MSG, pk);
      expect(r.valid).toBe(false);
      expect(r.disagreement).toBe(false);
    }
  });

  it('agrees with @noble/curves on a corrupted message and a corrupted key', () => {
    const { sig, pk } = freshSignature();
    const otherMsg = sha256(utf8('a different message'));
    expect(verify(sig, otherMsg, pk).valid).toBe(false);
    expect(verify(sig, otherMsg, pk).disagreement).toBe(false);
    const badPk = pk.slice();
    badPk[7] ^= 0x40;
    expect(verify(sig, MSG, badPk).disagreement).toBe(false);
  });

  it('rejects out-of-range and wrong-length inputs with a named stage', () => {
    const { sig, pk } = freshSignature();
    const cases: [Uint8Array, Uint8Array, RegExp][] = [
      [sig.subarray(0, 63), pk, /64 bytes/],
      [sig, pk.subarray(0, 31), /32 bytes/],
      [concat(bigTo32(P), sig.subarray(32)), pk, /R\.x ≥ field size/],
      [concat(sig.subarray(0, 32), bigTo32(N)), pk, /s ≥ group order/],
      [sig, bigTo32(P), /≥ field size p/],
      // x = 5 is not on the curve (from the spec's malformed-key vectors).
      [sig, bigTo32(5n), /not a valid x-coordinate/],
    ];
    for (const [s, p, pattern] of cases) {
      const r = verify(s, MSG, p);
      expect(r.valid).toBe(false);
      expect(r.reason).toMatch(pattern);
      expect(r.stages.at(-1)?.status).toBe('fail');
      expect(r.disagreement).toBe(false);
    }
  });

  it('reports the ordered stage pipeline for an accepted signature', () => {
    const { sig, pk } = freshSignature();
    const r = verify(sig, MSG, pk);
    expect(r.stages.map((s) => s.label)).toEqual([
      'Parse & lengths',
      'Range checks',
      'Lift point',
      'Challenge',
      'Group equation',
    ]);
    expect(r.stages.every((s) => s.status === 'pass')).toBe(true);
    expect(r.lhs).toBe(r.rhs); // both sides computed and equal
  });

  it('nobleVerify returns false rather than throwing on garbage', () => {
    expect(nobleVerify(new Uint8Array(0), MSG, new Uint8Array(0))).toBe(false);
    expect(nobleVerify(new Uint8Array(64), new Uint8Array(0), new Uint8Array(32))).toBe(false);
  });
});

describe('the challenge hash', () => {
  it('matches @noble/curves’ own tagged hash for the BIP-340 challenge', () => {
    const rx = hexToBytes('a'.repeat(64));
    const px = hexToBytes('b'.repeat(64));
    const expected = schnorr.utils.taggedHash('BIP0340/challenge', rx, px, MSG);
    expect(scalarHex(challenge(rx, px, MSG))).toBe(
      scalarHex(mod32(expected)),
    );
  });

  it('changes with every input', () => {
    const rx = hexToBytes('a'.repeat(64));
    const px = hexToBytes('b'.repeat(64));
    const base = challenge(rx, px, MSG);
    expect(challenge(px, px, MSG)).not.toBe(base);
    expect(challenge(rx, rx, MSG)).not.toBe(base);
    expect(challenge(rx, px, sha256(utf8('other')))).not.toBe(base);
  });
});

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

function mod32(b: Uint8Array): bigint {
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return x % N;
}

// Keep the hex helper exercised so a formatting regression cannot slip through.
describe('scalarHex', () => {
  it('always renders 32 bytes', () => {
    expect(scalarHex(1n)).toHaveLength(64);
    expect(scalarHex(1n)).toBe(bytesToHex(bigTo32(1n)));
  });
});
