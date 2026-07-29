import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { G, cbytes, cbytesExt, concatBytes, mul, randomScalar, utf8, xbytes, bytesToHex } from './field.js';
import { keyAgg } from './keyagg.js';
import { getSessionValues } from './sign.js';
import {
  grindSingleNonce,
  grindTwoNonce,
  nonceCoeff,
  randomTargetNonce,
} from './noncecontrol.js';

const MSG = sha256(utf8('choose my own challenge'));

function aggregateKeyPoint(count = 2) {
  const keys = Array.from({ length: count }, () => cbytes(mul(G, randomScalar())));
  return keyAgg(keys).Q;
}

describe('single nonce: the last signer controls the aggregate nonce exactly', () => {
  it('hits an arbitrary target every single time', () => {
    for (let i = 0; i < 20; i++) {
      const honest = [randomScalar(), randomScalar()];
      const target = randomTargetNonce();
      const r = grindSingleNonce(honest, target.point);
      expect(r.hitTarget).toBe(true);
      expect(r.achievedX).toBe(r.targetX);
      expect(r.b).toBeNull(); // there is no nonce coefficient in this scheme
    }
  });

  it('needs exactly one attempt — it is a subtraction, not a search', () => {
    const r = grindSingleNonce([randomScalar()], randomTargetNonce().point);
    expect(r.attempts).toHaveLength(1);
    expect(r.attackerNonces).toHaveLength(1);
  });

  it('scales with the number of honest signers', () => {
    for (const n of [1, 3, 5]) {
      const honest = Array.from({ length: n }, () => randomScalar());
      const r = grindSingleNonce(honest, randomTargetNonce().point);
      expect(r.honestNonces).toHaveLength(n);
      expect(r.hitTarget).toBe(true);
    }
  });
});

describe('two nonces: the b coefficient removes that control', () => {
  it('never lands on the target', () => {
    for (let i = 0; i < 10; i++) {
      const honest: [bigint, bigint][] = [
        [randomScalar(), randomScalar()],
        [randomScalar(), randomScalar()],
      ];
      const r = grindTwoNonce(honest, randomTargetNonce().point, aggregateKeyPoint(), MSG);
      expect(r.hitTarget).toBe(false);
      expect(r.achievedX).not.toBe(r.targetX);
      expect(r.attempts.every((a) => !a.hitTarget)).toBe(true);
    }
  });

  it('produces a different b every round — the fixed point keeps moving', () => {
    const honest: [bigint, bigint][] = [[randomScalar(), randomScalar()]];
    const r = grindTwoNonce(honest, randomTargetNonce().point, aggregateKeyPoint(), MSG, 5);
    expect(r.attempts).toHaveLength(5);
    const bs = r.attempts.map((a) => String(a.b));
    expect(new Set(bs).size).toBe(5);
  });

  it('the attacker still publishes two well-formed nonces — the attack is not blocked by validation', () => {
    const honest: [bigint, bigint][] = [[randomScalar(), randomScalar()]];
    const r = grindTwoNonce(honest, randomTargetNonce().point, aggregateKeyPoint(), MSG);
    expect(r.attackerNonces).toHaveLength(2);
    expect(r.attackerNonces.every((h) => h.length === 64)).toBe(true);
  });
});

describe('nonceCoeff', () => {
  it('agrees with the b that the real session derivation computes', () => {
    const keys = Array.from({ length: 2 }, () => cbytes(mul(G, randomScalar())));
    const ctx = keyAgg(keys);
    const R1 = mul(G, randomScalar());
    const R2 = mul(G, randomScalar());
    const aggnonce = concatBytes(cbytesExt(R1), cbytesExt(R2));
    const sv = getSessionValues({ aggnonce, pubkeys: keys, msg: MSG });
    expect(nonceCoeff(aggnonce, ctx.Q, MSG)).toBe(sv.b);
  });

  it('changes if the aggregate nonce, the aggregate key, or the message changes', () => {
    const Q = aggregateKeyPoint();
    const aggnonce = concatBytes(cbytesExt(mul(G, 3n)), cbytesExt(mul(G, 4n)));
    const other = concatBytes(cbytesExt(mul(G, 5n)), cbytesExt(mul(G, 4n)));
    const base = nonceCoeff(aggnonce, Q, MSG);
    expect(nonceCoeff(other, Q, MSG)).not.toBe(base);
    expect(nonceCoeff(aggnonce, aggregateKeyPoint(3), MSG)).not.toBe(base);
    expect(nonceCoeff(aggnonce, Q, sha256(utf8('other')))).not.toBe(base);
  });
});

describe('randomTargetNonce', () => {
  it('returns a point whose discrete log it also returns', () => {
    const t = randomTargetNonce();
    expect(t.point.equals(mul(G, t.secret))).toBe(true);
    expect(t.compressed).toBe(bytesToHex(cbytes(t.point)));
    expect(t.compressed).not.toBe(bytesToHex(xbytes(t.point)));
  });
});
