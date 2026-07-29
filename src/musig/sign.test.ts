import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  G,
  N,
  bigTo32,
  bytesToBig,
  bytesToHex,
  cbytes,
  hexToBytes,
  individualPubkey,
  mod,
  mul,
  randomScalar,
  utf8,
  xbytes,
} from './field.js';
import { nobleVerify, verify } from './bip340.js';
import { getXonlyPk, keyAgg, keyAggCoeff } from './keyagg.js';
import { nonceAgg, nonceGen } from './nonce.js';
import {
  type SessionContext,
  getSessionValues,
  partialSigAgg,
  partialSigVerify,
  partialSigVerifyInternal,
  sign,
} from './sign.js';

interface Party {
  sk: Uint8Array;
  pk: Uint8Array;
  secnonce: Uint8Array;
  pubnonce: Uint8Array;
}

function setup(count: number, msg: Uint8Array): { parties: Party[]; session: SessionContext } {
  const keys = Array.from({ length: count }, () => {
    const sk = bigTo32(randomScalar());
    return { sk, pk: individualPubkey(sk) };
  });
  const pubkeys = keys.map((k) => k.pk);
  const aggpk = getXonlyPk(keyAgg(pubkeys));
  const parties: Party[] = keys.map((k) => {
    const { secnonce, pubnonce } = nonceGen(k.sk, k.pk, aggpk, msg);
    return { ...k, secnonce, pubnonce };
  });
  const aggnonce = nonceAgg(parties.map((p) => p.pubnonce));
  return { parties, session: { aggnonce, pubkeys, msg } };
}

const MSG = sha256(utf8('release the multisig funds'));

describe('the full two-round protocol', () => {
  for (const n of [2, 3, 4, 5]) {
    it(`${n}-of-${n}: aggregates to one signature a plain BIP-340 verifier accepts`, () => {
      const { parties, session } = setup(n, MSG);
      const psigs = parties.map((p) => sign(p.secnonce, p.sk, session).psig);

      // Each partial verifies on its own — this is what makes failures attributable.
      psigs.forEach((psig, i) => {
        expect(
          partialSigVerify(psig, parties.map((p) => p.pubnonce), session.pubkeys, MSG, i),
        ).toBe(true);
      });

      const { sig } = partialSigAgg(psigs, session);
      const aggpk = getXonlyPk(keyAgg(session.pubkeys));

      expect(sig).toHaveLength(64);
      // Hand-rolled verifier, and @noble/curves' independent one, must both accept.
      const result = verify(sig, MSG, aggpk);
      expect(result.valid).toBe(true);
      expect(result.nobleValid).toBe(true);
      expect(result.disagreement).toBe(false);
    });
  }

  it('the aggregate signature is byte-identical in size and shape to a single-signer one', () => {
    const { parties, session } = setup(3, MSG);
    const psigs = parties.map((p) => sign(p.secnonce, p.sk, session).psig);
    const { sig } = partialSigAgg(psigs, session);
    const aggpk = getXonlyPk(keyAgg(session.pubkeys));
    expect(sig.length).toBe(64);
    expect(aggpk.length).toBe(32);
    // Nothing in the signature encodes the signer count.
    expect(nobleVerify(sig, MSG, aggpk)).toBe(true);
  });

  it('Σ s_i really is the s in the finished signature (untweaked)', () => {
    const { parties, session } = setup(3, MSG);
    const psigs = parties.map((p) => sign(p.secnonce, p.sk, session).psig);
    const { sig, trace } = partialSigAgg(psigs, session);
    const summed = psigs.reduce((acc, p) => mod(acc + bytesToBig(p), N), 0n);
    expect(trace.tweakCorrection).toBe(0n);
    expect(trace.s).toBe(summed);
    expect(bytesToHex(sig.subarray(32))).toBe(bytesToHex(bigTo32(summed)));
  });

  it('each partial signature satisfies s_i = k_i1 + b·k_i2 + e·a_i·d_i', () => {
    const { parties, session } = setup(3, MSG);
    const { b, e, Q } = getSessionValues(session);
    const g = mod(Q.y, 2n) === 0n ? 1n : N - 1n;
    parties.forEach((p) => {
      const k1 = bytesToBig(p.secnonce.subarray(0, 32));
      const k2 = bytesToBig(p.secnonce.subarray(32, 64));
      const { R } = getSessionValues(session);
      const flip = mod(R.y, 2n) === 0n;
      const { psig } = sign(p.secnonce, p.sk, session);
      const a = keyAggCoeff(session.pubkeys, p.pk);
      const d = mod(g * bytesToBig(p.sk), N);
      const expected = mod(
        (flip ? k1 : N - k1) + b * (flip ? k2 : N - k2) + e * a * d,
        N,
      );
      expect(bytesToBig(psig)).toBe(expected);
    });
  });

  it('the aggregate key and nonce are what the signature commits to', () => {
    const { parties, session } = setup(2, MSG);
    const { R } = getSessionValues(session);
    const psigs = parties.map((p) => sign(p.secnonce, p.sk, session).psig);
    const { sig } = partialSigAgg(psigs, session);
    expect(bytesToHex(sig.subarray(0, 32))).toBe(bytesToHex(xbytes(R)));
  });
});

describe('fail-closed behaviour', () => {
  it('consumes the secnonce: a second sign() with the same object throws', () => {
    const { parties, session } = setup(2, MSG);
    const p = parties[0];
    expect(() => sign(p.secnonce, p.sk, session)).not.toThrow();
    expect(() => sign(p.secnonce, p.sk, session)).toThrow(/out of range/);
  });

  it('refuses to sign when the secret key does not match the nonce commitment', () => {
    const { parties, session } = setup(2, MSG);
    const wrongSk = bigTo32(randomScalar());
    expect(() => sign(parties[0].secnonce, wrongSk, session)).toThrow(/does not match/);
  });

  it('refuses a secret key outside [1, n-1]', () => {
    const { parties, session } = setup(2, MSG);
    expect(() => sign(parties[0].secnonce, bigTo32(0n), session)).toThrow(/out of range/);
  });

  it('refuses to sign for a key list the signer is not in', () => {
    const { session } = setup(2, MSG);
    const stranger = bigTo32(randomScalar());
    const strangerPk = individualPubkey(stranger);
    const { secnonce } = nonceGen(stranger, strangerPk, null, MSG);
    expect(() => sign(secnonce, stranger, session)).toThrow(/must be included/);
  });

  it('rejects a partial signature ≥ n and a wrong-length one', () => {
    const { parties, session } = setup(2, MSG);
    expect(
      partialSigVerifyInternal(bigTo32(N), parties[0].pubnonce, parties[0].pk, session),
    ).toBe(false);
    expect(
      partialSigVerifyInternal(new Uint8Array(31), parties[0].pubnonce, parties[0].pk, session),
    ).toBe(false);
  });

  it('rejects one signer’s partial signature checked against another signer', () => {
    const { parties, session } = setup(3, MSG);
    const psig0 = sign(parties[0].secnonce, parties[0].sk, session).psig;
    expect(
      partialSigVerify(psig0, parties.map((p) => p.pubnonce), session.pubkeys, MSG, 0),
    ).toBe(true);
    expect(
      partialSigVerify(psig0, parties.map((p) => p.pubnonce), session.pubkeys, MSG, 1),
    ).toBe(false);
  });

  it('rejects the negation of a valid partial signature', () => {
    const { parties, session } = setup(2, MSG);
    const psig = sign(parties[0].secnonce, parties[0].sk, session).psig;
    const negated = bigTo32(mod(N - bytesToBig(psig), N));
    expect(partialSigVerifyInternal(negated, parties[0].pubnonce, parties[0].pk, session)).toBe(
      false,
    );
  });

  it('a single flipped bit in one partial makes the aggregate signature invalid, and names the signer', () => {
    const { parties, session } = setup(3, MSG);
    const psigs = parties.map((p) => sign(p.secnonce, p.sk, session).psig);
    const tampered = psigs.map((p, i) => {
      if (i !== 1) return p;
      const bad = p.slice();
      bad[31] ^= 0x01;
      return bad;
    });
    const verdicts = tampered.map((p, i) =>
      partialSigVerify(p, parties.map((q) => q.pubnonce), session.pubkeys, MSG, i),
    );
    expect(verdicts).toEqual([true, false, true]); // the culprit is identified

    const { sig } = partialSigAgg(tampered, session);
    const aggpk = getXonlyPk(keyAgg(session.pubkeys));
    expect(verify(sig, MSG, aggpk).valid).toBe(false);
    expect(nobleVerify(sig, MSG, aggpk)).toBe(false);
  });

  it('rejects a mismatched pubnonce/pubkey list length', () => {
    const { parties, session } = setup(2, MSG);
    const psig = sign(parties[0].secnonce, parties[0].sk, session).psig;
    expect(() =>
      partialSigVerify(psig, [parties[0].pubnonce], session.pubkeys, MSG, 0),
    ).toThrow(/same length/);
  });

  it('detects a malformed aggregate nonce', () => {
    const { session } = setup(2, MSG);
    const bad = session.aggnonce.slice();
    bad[0] = 4;
    expect(() => getSessionValues({ ...session, aggnonce: bad })).toThrow(/aggnonce/);
  });
});

describe('n-of-n, not t-of-n', () => {
  it('a subset of signers cannot produce a signature for the full key list', () => {
    const msg = sha256(utf8('partial quorum attempt'));
    const keys = Array.from({ length: 3 }, () => {
      const sk = bigTo32(randomScalar());
      return { sk, pk: individualPubkey(sk) };
    });
    const pubkeys = keys.map((k) => k.pk);
    const aggpk = getXonlyPk(keyAgg(pubkeys));

    // Only two of the three show up.
    const subset = keys.slice(0, 2);
    const nonces = subset.map((k) => nonceGen(k.sk, k.pk, aggpk, msg));
    const session: SessionContext = {
      aggnonce: nonceAgg(nonces.map((n) => n.pubnonce)),
      pubkeys,
      msg,
    };
    const psigs = subset.map((k, i) => sign(nonces[i].secnonce, k.sk, session).psig);
    const { sig } = partialSigAgg(psigs, session);

    expect(verify(sig, msg, aggpk).valid).toBe(false);
    expect(nobleVerify(sig, msg, aggpk)).toBe(false);
  });
});

describe('edge cases the spec calls out', () => {
  it('handles an aggregate nonce whose halves are both infinity', () => {
    // Two signers with exactly negating nonce pairs: R_1 and R_2 both cancel, so
    // R' = infinity and the spec's R = G fallback must kick in.
    const msg = sha256(utf8('infinity fallback'));
    const skA = bigTo32(randomScalar());
    const skB = bigTo32(randomScalar());
    const pubkeys = [individualPubkey(skA), individualPubkey(skB)];
    const k1 = randomScalar();
    const k2 = randomScalar();
    const pnA = concatPair(cbytes(mul(G, k1)), cbytes(mul(G, k2)));
    const pnB = concatPair(cbytes(mul(G, N - k1)), cbytes(mul(G, N - k2)));
    const aggnonce = nonceAgg([pnA, pnB]);
    expect(bytesToHex(aggnonce)).toBe('00'.repeat(66));

    const sv = getSessionValues({ aggnonce, pubkeys, msg });
    expect(sv.usedInfinityFallback).toBe(true);
    expect(sv.R.equals(G)).toBe(true);
  });

  it('a session over an empty message still works end to end', () => {
    const msg = new Uint8Array(32); // 32 zero bytes, the all-zero digest
    const { parties, session } = setup(2, msg);
    const psigs = parties.map((p) => sign(p.secnonce, p.sk, session).psig);
    const { sig } = partialSigAgg(psigs, session);
    expect(nobleVerify(sig, msg, getXonlyPk(keyAgg(session.pubkeys)))).toBe(true);
  });

  it('two identical signers (the same key twice) still aggregate correctly', () => {
    const msg = sha256(utf8('same key twice'));
    const sk = bigTo32(randomScalar());
    const pk = individualPubkey(sk);
    const pubkeys = [pk, pk];
    const aggpk = getXonlyPk(keyAgg(pubkeys));
    const n1 = nonceGen(sk, pk, aggpk, msg);
    const n2 = nonceGen(sk, pk, aggpk, msg, hexToBytes('02'));
    const session: SessionContext = { aggnonce: nonceAgg([n1.pubnonce, n2.pubnonce]), pubkeys, msg };
    const psigs = [sign(n1.secnonce, sk, session).psig, sign(n2.secnonce, sk, session).psig];
    const { sig } = partialSigAgg(psigs, session);
    expect(nobleVerify(sig, msg, aggpk)).toBe(true);
  });
});

function concatPair(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(66);
  out.set(a);
  out.set(b, 33);
  return out;
}
