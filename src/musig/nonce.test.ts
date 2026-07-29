import { describe, expect, it } from 'vitest';
import {
  G,
  add,
  bigTo32,
  bytesToHex,
  cbytes,
  cpoint,
  cpointExt,
  hexToBytes,
  individualPubkey,
  mul,
  negate,
  randomBytes,
  randomScalar,
  xbytes,
} from './field.js';
import { InvalidContributionError } from './keyagg.js';
import { nonceAgg, nonceAggWithTrace, nonceGen, nonceGenInternal } from './nonce.js';

const skFor = () => bigTo32(randomScalar());

describe('NonceGen', () => {
  it('produces two nonces, and the pubnonce is their two public points', () => {
    const sk = skFor();
    const pk = individualPubkey(sk);
    const { secnonce, pubnonce, k1, k2 } = nonceGen(sk, pk, null, null);
    expect(secnonce).toHaveLength(97);
    expect(pubnonce).toHaveLength(66);
    expect(bytesToHex(pubnonce.subarray(0, 33))).toBe(bytesToHex(cbytes(mul(G, k1))));
    expect(bytesToHex(pubnonce.subarray(33, 66))).toBe(bytesToHex(cbytes(mul(G, k2))));
    // The signer's own key is carried along so `sign` can refuse a mismatched key.
    expect(bytesToHex(secnonce.subarray(64, 97))).toBe(bytesToHex(pk));
  });

  it('the two nonces are different', () => {
    const sk = skFor();
    const { k1, k2 } = nonceGen(sk, individualPubkey(sk), null, null);
    expect(k1).not.toBe(k2);
  });

  it('is deterministic in its inputs — same rand, same nonces', () => {
    const rand = randomBytes(32);
    const sk = skFor();
    const pk = individualPubkey(sk);
    const a = nonceGenInternal(rand, sk, pk, null, null, null);
    const b = nonceGenInternal(rand, sk, pk, null, null, null);
    expect(bytesToHex(a.secnonce)).toBe(bytesToHex(b.secnonce));
  });

  it('changes with the message, the aggregate key, and extra input', () => {
    const rand = randomBytes(32);
    const sk = skFor();
    const pk = individualPubkey(sk);
    const base = nonceGenInternal(rand, sk, pk, null, null, null);
    const withMsg = nonceGenInternal(rand, sk, pk, null, new Uint8Array(32), null);
    const withAgg = nonceGenInternal(rand, sk, pk, new Uint8Array(32), null, null);
    const withExtra = nonceGenInternal(rand, sk, pk, null, null, hexToBytes('01'));
    const hexes = [base, withMsg, withAgg, withExtra].map((r) => bytesToHex(r.secnonce));
    expect(new Set(hexes).size).toBe(4);
  });

  it('distinguishes an absent message from a present empty message', () => {
    const rand = randomBytes(32);
    const sk = skFor();
    const pk = individualPubkey(sk);
    const absent = nonceGenInternal(rand, sk, pk, null, null, null);
    const empty = nonceGenInternal(rand, sk, pk, null, new Uint8Array(0), null);
    expect(bytesToHex(absent.secnonce)).not.toBe(bytesToHex(empty.secnonce));
  });

  it('hardens the caller randomness with the secret key when one is supplied', () => {
    const rand = randomBytes(32);
    const sk = skFor();
    const pk = individualPubkey(sk);
    const hardened = nonceGenInternal(rand, sk, pk, null, null, null);
    const raw = nonceGenInternal(rand, null, pk, null, null, null);
    expect(bytesToHex(hardened.secnonce)).not.toBe(bytesToHex(raw.secnonce));
  });

  it('rejects a wrong-length sk or aggpk', () => {
    const sk = skFor();
    const pk = individualPubkey(sk);
    expect(() => nonceGen(new Uint8Array(31), pk, null, null)).toThrow(/length 32/);
    expect(() => nonceGen(sk, pk, new Uint8Array(31), null)).toThrow(/length 32/);
  });
});

describe('NonceAgg', () => {
  it('sums each half independently', () => {
    const pns = [1, 2, 3].map(() => {
      const sk = skFor();
      return nonceGen(sk, individualPubkey(sk), null, null);
    });
    const aggnonce = nonceAgg(pns.map((p) => p.pubnonce));
    const expected1 = pns.slice(1).reduce((acc, p) => add(acc, mul(G, p.k1)), mul(G, pns[0].k1));
    const expected2 = pns.slice(1).reduce((acc, p) => add(acc, mul(G, p.k2)), mul(G, pns[0].k2));
    expect(bytesToHex(aggnonce.subarray(0, 33))).toBe(bytesToHex(cbytes(expected1)));
    expect(bytesToHex(aggnonce.subarray(33, 66))).toBe(bytesToHex(cbytes(expected2)));
  });

  it('serializes a cancelled half as 33 zero bytes rather than failing', () => {
    // Two signers whose second nonces are exact negations: R_2 sums to infinity.
    const k = randomScalar();
    const pn1 = concat(cbytes(mul(G, randomScalar())), cbytes(mul(G, k)));
    const pn2 = concat(cbytes(mul(G, randomScalar())), cbytes(negate(mul(G, k))));
    const aggnonce = nonceAgg([pn1, pn2]);
    expect(bytesToHex(aggnonce.subarray(33, 66))).toBe('00'.repeat(33));
    expect(cpointExt(aggnonce.subarray(33, 66)).is0()).toBe(true);
    // The first half is unaffected — the halves really are independent.
    expect(cpoint(aggnonce.subarray(0, 33)).is0()).toBe(false);
  });

  it('names the offending signer on a malformed pubnonce', () => {
    const sk = skFor();
    const good = nonceGen(sk, individualPubkey(sk), null, null).pubnonce;
    const bad = good.slice();
    bad[0] = 4; // invalid prefix byte, the spec's own error shape
    try {
      nonceAgg([good, bad]);
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidContributionError);
      expect((err as InvalidContributionError).signer).toBe(1);
      expect((err as InvalidContributionError).contrib).toBe('pubnonce');
    }
  });

  it('rejects an empty nonce list', () => {
    expect(() => nonceAgg([])).toThrow(/empty/);
  });

  it('the trace reports every signer contribution and the sum', () => {
    const pns = [1, 2].map(() => {
      const sk = skFor();
      return nonceGen(sk, individualPubkey(sk), null, null).pubnonce;
    });
    const { aggnonce, trace } = nonceAggWithTrace(pns);
    expect(trace.first.perSigner).toHaveLength(2);
    expect(trace.second.perSigner).toHaveLength(2);
    expect(trace.aggnonceHex).toBe(bytesToHex(aggnonce));
    expect(trace.first.sum).toBe(bytesToHex(xbytes(cpointExt(aggnonce.subarray(0, 33)))));
    expect(trace.first.isInfinity).toBe(false);
  });
});

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}
