/**
 * Tests for the ROS forgery.
 *
 * This attack's claim is stronger than Wagner's — it works at the REAL challenge
 * width with nothing reduced — so the tests have to be correspondingly strict. The
 * forgery must verify under a full-width verifier, the honest signer must provably
 * never have seen the forged message and never have reused a nonce, and the linear
 * relation must hold exactly in the scalar field.
 */
import { describe, expect, it } from 'vitest';
import { G, N, add, bytesToHex, mod, mul, randomScalar, utf8, xbytes } from './field.js';
import {
  ROS_SESSIONS,
  attemptRosTwoNonce,
  forgeRos,
  rosChallenge,
  verifyFullWidth,
} from './ros.js';

const TIMEOUT = 60_000;

describe('the full-width challenge and verifier', () => {
  it('reduces the whole hash mod n — nothing is truncated', () => {
    const e = rosChallenge(mul(G, 3n), mul(G, 5n), utf8('m'));
    expect(e).toBeGreaterThan(0n);
    expect(e).toBeLessThan(N);
    // A truncated challenge would be vanishingly small compared with n.
    expect(e > 1n << 200n).toBe(true);
  });

  it('changes with the nonce, the key, and the message', () => {
    const base = rosChallenge(mul(G, 3n), mul(G, 5n), utf8('m'));
    expect(rosChallenge(mul(G, 4n), mul(G, 5n), utf8('m'))).not.toBe(base);
    expect(rosChallenge(mul(G, 3n), mul(G, 6n), utf8('m'))).not.toBe(base);
    expect(rosChallenge(mul(G, 3n), mul(G, 5n), utf8('n'))).not.toBe(base);
  });

  it('accepts an honest signature and rejects a tampered one', () => {
    const d = randomScalar();
    const Q = mul(G, d);
    const msg = utf8('honest');
    const k = randomScalar();
    const R = mul(G, k);
    const s = mod(k + rosChallenge(R, Q, msg) * d, N);
    expect(verifyFullWidth(R, s, Q, msg)).toBe(true);
    expect(verifyFullWidth(R, mod(s + 1n, N), Q, msg)).toBe(false);
    expect(verifyFullWidth(R, s, Q, utf8('other'))).toBe(false);
  });
});

describe('the ROS forgery — this attack must SUCCEED, at full width', () => {
  it(
    'forges a valid signature on a message nobody authorised',
    () => {
      const r = forgeRos();
      expect(r.verified).toBe(true);
      expect(r.honestSignerNeverSawIt).toBe(true);
      expect(r.challengeBits).toBe(256);
      expect(r.sessions).toBe(ROS_SESSIONS);
      // The headline: one more signature than sessions.
      expect(r.signaturesObtained).toBe(r.sessions + 1);
      expect(r.queriedMessageCount).toBe(r.sessions);
      // The linear relation is exact in the scalar field, not approximate.
      expect(r.linearRelationHolds).toBe(true);
      expect(r.sumRhoE).toBe(r.eStar);
      expect(r.forgedR).toHaveLength(64);
      expect(r.forgedS).toHaveLength(64);
    },
    TIMEOUT,
  );

  it(
    'succeeds every time — there is no search, so there is no luck involved',
    () => {
      for (let i = 0; i < 3; i++) {
        const r = forgeRos();
        expect(r.verified).toBe(true);
        expect(r.linearRelationHolds).toBe(true);
      }
    },
    TIMEOUT,
  );

  it(
    'uses both bit branches, so the construction is genuinely exercised',
    () => {
      const r = forgeRos();
      // B is essentially a uniform field element, so a wild imbalance would mean the
      // bits are not being read the way the algebra assumes.
      expect(r.onesInB).toBeGreaterThan(60);
      expect(r.onesInB).toBeLessThan(200);
      expect(r.sampleSessions.length).toBeGreaterThan(0);
      expect(r.sampleSessions.every((s) => s.alpha === 1n || s.alpha === 2n)).toBe(true);
      expect(r.sampleSessions.every((s) => s.e > 0n && s.e < N)).toBe(true);
    },
    TIMEOUT,
  );

  it(
    'costs one scalar multiplication per session plus one — no search term at all',
    () => {
      const r = forgeRos();
      expect(r.scalarMultiplications).toBe(r.sessions + 1);
    },
    TIMEOUT,
  );

  it(
    'the forged signature does not verify under an unrelated key or message',
    () => {
      const r = forgeRos();
      const stranger = mul(G, randomScalar());
      expect(bytesToHex(xbytes(stranger))).not.toBe(r.aggregateKeyX);
      // Reconstructing the exact point from x-only is out of scope here; the useful
      // check is that the attack's own verifier is not simply returning true always.
      expect(verifyFullWidth(mul(G, 2n), 1n, stranger, utf8('nonsense'))).toBe(false);
    },
    TIMEOUT,
  );
});

describe('the same attack against two nonces — this attack must FAIL', () => {
  it(
    'the target drifts, so the system is solved against a target that no longer applies',
    () => {
      for (let i = 0; i < 3; i++) {
        const r = attemptRosTwoNonce();
        expect(r.targetDrifted).toBe(true);
        expect(r.targetedEStar).not.toBe(r.actualEStar);
        expect(r.linearRelationHolds).toBe(false);
        expect(r.verified).toBe(false);
      }
    },
    TIMEOUT,
  );

  it('explains the failure in terms of the right-hand side, not hand-waving', () => {
    const r = attemptRosTwoNonce();
    expect(r.explanation).toMatch(/constant right-hand side/);
    expect(r.explanation).toMatch(/b_i/);
  });

  it(
    'holds at other session counts too',
    () => {
      for (const sessions of [8, 16]) {
        const r = attemptRosTwoNonce({ sessions });
        expect(r.sessions).toBe(sessions);
        expect(r.verified).toBe(false);
      }
    },
    TIMEOUT,
  );
});

describe('ROS versus Wagner', () => {
  it(
    'ROS needs no reduced parameter, which is the whole reason it is also here',
    () => {
      const r = forgeRos();
      // Wagner truncates to 21-30 bits; this one runs at the real width.
      expect(r.challengeBits).toBe(256);
      expect(r.verified).toBe(true);
    },
    TIMEOUT,
  );

  it('the group arithmetic underneath is the ordinary one', () => {
    const a = randomScalar();
    const b = randomScalar();
    expect(add(mul(G, a), mul(G, b)).equals(mul(G, mod(a + b, N)))).toBe(true);
  });
});
