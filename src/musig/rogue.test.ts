import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { G, bytesToHex, cbytes, mul, randomScalar, utf8, xbytes } from './field.js';
import { verify } from './bip340.js';
import { keyAgg } from './keyagg.js';
import { naiveKeyAgg, naiveSign } from './naive.js';
import { attemptBip327Rogue, naiveRogueAttack, soloSign, tryRogueKey } from './rogue.js';

const MSG = sha256(utf8('pay the attacker everything'));

describe('the naive scheme works when everyone is honest', () => {
  it('produces a signature a plain BIP-340 verifier accepts', () => {
    const signers = [1, 2, 3].map(() => ({ d: randomScalar(), k: randomScalar() }));
    const result = naiveSign(signers, MSG);
    expect(verify(result.signature, MSG, result.aggregateKeyX).valid).toBe(true);
  });

  it('sums keys with no coefficients at all', () => {
    const secrets = [randomScalar(), randomScalar()];
    const keys = secrets.map((d) => cbytes(mul(G, d)));
    const naive = naiveKeyAgg(keys);
    expect(naive.equals(mul(G, secrets[0] + secrets[1]))).toBe(true);
    // The BIP-327 aggregate is a different point entirely.
    expect(keyAgg(keys).Q.equals(naive)).toBe(false);
  });
});

describe('rogue-key attack against naive aggregation', () => {
  it('lets the attacker own the aggregate key outright', () => {
    const honest = [randomScalar(), randomScalar()];
    const r = naiveRogueAttack(honest, MSG);
    expect(r.attackerOwnsAggregate).toBe(true);
  });

  it('forges a signature the REAL verifier accepts, with no honest signer involved', () => {
    for (let i = 0; i < 8; i++) {
      const honest = [randomScalar(), randomScalar()];
      const r = naiveRogueAttack(honest, MSG);
      expect(r.verdict.valid).toBe(true);
      expect(r.verdict.nobleValid).toBe(true); // independent verifier agrees
      expect(r.verdict.disagreement).toBe(false);
    }
  });

  it('the rogue key is a perfectly well-formed public key — no validity check can catch it', () => {
    const honest = [randomScalar()];
    const r = naiveRogueAttack(honest, MSG);
    expect(r.roguePubkey).toHaveLength(66);
    expect(['02', '03']).toContain(r.roguePubkey.slice(0, 2));
  });

  it('scales to any number of honest signers', () => {
    for (const n of [1, 2, 3, 4]) {
      const honest = Array.from({ length: n }, () => randomScalar());
      expect(naiveRogueAttack(honest, MSG).verdict.valid).toBe(true);
    }
  });
});

describe('the same attack against BIP-327 aggregation', () => {
  it('never lands on the attacker’s target key', () => {
    for (let i = 0; i < 5; i++) {
      const honest = [randomScalar(), randomScalar()];
      const r = attemptBip327Rogue(honest, MSG);
      expect(r.attackerOwnsAggregate).toBe(false);
      expect(r.rounds.every((round) => !round.hitTarget)).toBe(true);
      expect(r.aggregateKeyX).not.toBe(r.targetKeyX);
    }
  });

  it('the forgery is REJECTED by the real verifier', () => {
    for (let i = 0; i < 5; i++) {
      const honest = [randomScalar(), randomScalar()];
      const r = attemptBip327Rogue(honest, MSG);
      expect(r.verdict.valid).toBe(false);
      expect(r.verdict.nobleValid).toBe(false);
      expect(r.verdict.disagreement).toBe(false);
    }
  });

  it('logs a real iteration attempt per round, each with a different coefficient', () => {
    const r = attemptBip327Rogue([randomScalar(), randomScalar()], MSG, 4);
    expect(r.rounds).toHaveLength(4);
    expect(new Set(r.rounds.map((x) => x.candidate)).size).toBe(4);
    expect(new Set(r.rounds.map((x) => x.actualCoeff.toString())).size).toBe(4);
  });
});

describe('hand-supplied rogue keys', () => {
  it('accepts the classic subtraction under naive aggregation and rejects it under BIP-327', () => {
    const honest = [randomScalar()];
    const t = randomScalar();
    const roguePoint = mul(G, t).add(mul(G, honest[0]).negate());
    const rogueHex = bytesToHex(cbytes(roguePoint));

    const naive = tryRogueKey(honest, rogueHex, t, MSG, 'naive');
    expect(naive.attackerOwnsAggregate).toBe(true);
    expect(naive.verdict.valid).toBe(true);

    const bip327 = tryRogueKey(honest, rogueHex, t, MSG, 'bip327');
    expect(bip327.attackerOwnsAggregate).toBe(false);
    expect(bip327.verdict.valid).toBe(false);
  });

  it('rejects a malformed rogue key instead of pretending it worked', () => {
    expect(() => tryRogueKey([randomScalar()], 'not hex', 1n, MSG, 'naive')).toThrow();
    expect(() => tryRogueKey([randomScalar()], '02' + '05'.padStart(64, '0'), 1n, MSG, 'naive')).toThrow();
  });
});

describe('soloSign', () => {
  it('produces a valid single-signer BIP-340 signature for the key it claims', () => {
    const secret = randomScalar();
    const { sig, pubkeyX } = soloSign(secret, MSG);
    expect(bytesToHex(pubkeyX)).toBe(bytesToHex(xbytes(mul(G, secret))));
    expect(verify(sig, MSG, pubkeyX).valid).toBe(true);
  });

  it('does not verify under an unrelated key', () => {
    const { sig } = soloSign(randomScalar(), MSG);
    expect(verify(sig, MSG, xbytes(mul(G, randomScalar()))).valid).toBe(false);
  });
});
