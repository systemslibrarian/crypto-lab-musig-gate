/**
 * Why TWO nonces — the capability that a single nonce hands to the last signer,
 * and how the coefficient b takes it away.
 *
 * SINGLE NONCE (broken).  R = ΣR_i is linear. The last signer to publish picks
 *
 *     R_last = R_target − Σ_{i<u} R_i
 *
 * and the group's aggregate nonce is exactly R_target — chosen, not random. Since
 * the challenge is e = H(R ‖ Q ‖ m), the attacker now chooses e. `grindSingleNonce`
 * does this subtraction for real and lands on the target every time, exactly.
 *
 * TWO NONCES (BIP-327).  R = R_1 + b·R_2 with b = H(aggnonce ‖ Q ‖ m). The same
 * subtraction still works arithmetically — but the moment the attacker's nonce
 * changes the aggnonce bytes, b changes, so R moves off the target.
 * `grindTwoNonce` runs the same attack, iterating the fixed point, and reports the
 * miss. Convergence would require inverting SHA-256.
 *
 * WHAT THIS DOES AND DOES NOT SHOW.  Controlling the aggregate nonce is the
 * *capability*; turning it into a forgery is a second step — Wagner's
 * generalised-birthday algorithm over k concurrent sessions (Drijvers et al.,
 * "On the Security of Two-Round Multi-Signatures", 2019), or the polynomial-time
 * ROS attack of Benhamouda et al. (2020) with ~log₂ n concurrent sessions. Neither
 * search is run here — a k-list birthday search is not a browser-tab workload, and
 * faking it would be worse than omitting it. What is real here is the capability
 * itself, its exact removal by b, and the honest statement of what closes the gap.
 */
import {
  G,
  INFINITY,
  N,
  type Pt,
  add,
  bytesToBig,
  bytesToHex,
  cbytes,
  cbytesExt,
  concatBytes,
  mod,
  mul,
  negate,
  randomScalar,
  taggedHash,
  xbytes,
} from './field.js';
import { sumPoints } from './naive.js';

export interface GrindResult {
  /** Which scheme was attacked. */
  scheme: 'single-nonce' | 'two-nonce';
  /** x-only hex of the nonce the attacker was aiming at. */
  targetX: string;
  /** x-only hex of the aggregate nonce actually produced. */
  achievedX: string;
  /** True only when the attacker landed exactly on the target. */
  hitTarget: boolean;
  /** The honest signers' individual nonce points, x-only hex. */
  honestNonces: string[];
  /** The nonce(s) the attacker published, x-only hex. */
  attackerNonces: string[];
  /** Per-attempt log — one entry for the single-nonce case, several for two-nonce. */
  attempts: GrindAttempt[];
  /** Nonce coefficient in play, or null for the single-nonce scheme (there is none). */
  b: bigint | null;
}

export interface GrindAttempt {
  round: number;
  /** b as computed from the aggnonce this round proposed (null for single-nonce). */
  b: bigint | null;
  achievedX: string;
  hitTarget: boolean;
}

/**
 * BROKEN SCHEME: one nonce each, R = ΣR_i. The attacker publishes last and hits
 * any target it likes with a single subtraction. Real points, no search.
 */
export function grindSingleNonce(honestNonceSecrets: bigint[], targetR: Pt): GrindResult {
  const honestPoints = honestNonceSecrets.map((k) => mul(G, k));
  let sumHonest: Pt = INFINITY;
  for (const pt of honestPoints) sumHonest = add(sumHonest, pt);

  // The whole attack.
  const attackerNonce = add(targetR, negate(sumHonest));
  if (attackerNonce.is0()) throw new Error('degenerate target (pick a different target nonce)');

  const achieved = sumPoints([...honestPoints, attackerNonce], 'aggregate nonce');
  const hitTarget = achieved.equals(targetR);

  return {
    scheme: 'single-nonce',
    targetX: bytesToHex(xbytes(targetR)),
    achievedX: bytesToHex(xbytes(achieved)),
    hitTarget,
    honestNonces: honestPoints.map((pt) => bytesToHex(xbytes(pt))),
    attackerNonces: [bytesToHex(xbytes(attackerNonce))],
    attempts: [{ round: 1, b: null, achievedX: bytesToHex(xbytes(achieved)), hitTarget }],
    b: null,
  };
}

/** b = int(H_"MuSig/noncecoef"(aggnonce ‖ xbytes(Q) ‖ m)) mod n. */
export function nonceCoeff(aggnonce: Uint8Array, Q: Pt, msg: Uint8Array): bigint {
  return mod(bytesToBig(taggedHash('MuSig/noncecoef', aggnonce, xbytes(Q), msg)), N);
}

/**
 * BIP-327: two nonces each, R = R_1 + b·R_2. The attacker runs the same
 * subtraction, discovers b has moved, feeds the new b back in, and repeats.
 *
 * Each round is a genuine attempt: we compute the aggnonce the attacker's choice
 * produces, derive the real b from those bytes, and evaluate the real
 * R = R_1 + b·R_2. `hitTarget` is only ever true if the arithmetic really lands
 * on the target.
 */
export function grindTwoNonce(
  honestNoncePairs: [bigint, bigint][],
  targetR: Pt,
  Q: Pt,
  msg: Uint8Array,
  maxRounds = 6,
): GrindResult {
  const honest1 = honestNoncePairs.map(([k1]) => mul(G, k1));
  const honest2 = honestNoncePairs.map(([, k2]) => mul(G, k2));
  let sum1: Pt = INFINITY;
  for (const pt of honest1) sum1 = add(sum1, pt);
  let sum2: Pt = INFINITY;
  for (const pt of honest2) sum2 = add(sum2, pt);

  // The attacker's second nonce is fixed (it has to publish something); only the
  // first is solved for. Giving the attacker BOTH degrees of freedom does not help:
  // b still depends on the bytes of whatever it publishes.
  const attackerK2 = randomScalar();
  const attackerR2 = mul(G, attackerK2);

  const attempts: GrindAttempt[] = [];
  let bGuess = 1n;
  let attackerR1: Pt = mul(G, randomScalar());
  let achieved: Pt = INFINITY;
  let bActual = 0n;

  for (let round = 1; round <= maxRounds; round++) {
    // Solve  R_target = (sum1 + R_1^att) + b·(sum2 + R_2^att)  for R_1^att, using
    // the b the attacker currently believes.
    const R2total = add(sum2, attackerR2);
    attackerR1 = add(add(targetR, negate(mul(R2total, bGuess))), negate(sum1));
    if (attackerR1.is0()) {
      attackerR1 = mul(G, randomScalar());
    }

    // Now compute what the protocol REALLY does with that choice.
    const R1total = add(sum1, attackerR1);
    const aggnonce = concatBytes(cbytesExt(R1total), cbytesExt(R2total));
    bActual = nonceCoeff(aggnonce, Q, msg);
    achieved = add(R1total, mul(R2total, bActual));
    const hit = !achieved.is0() && achieved.equals(targetR);
    attempts.push({
      round,
      b: bActual,
      achievedX: achieved.is0() ? '∞' : bytesToHex(xbytes(achieved)),
      hitTarget: hit,
    });
    if (hit) break; // would mean SHA-256 is invertible
    bGuess = bActual; // feed the real b back in and try again
  }

  const hitTarget = !achieved.is0() && achieved.equals(targetR);
  return {
    scheme: 'two-nonce',
    targetX: bytesToHex(xbytes(targetR)),
    achievedX: achieved.is0() ? '∞' : bytesToHex(xbytes(achieved)),
    hitTarget,
    honestNonces: honest1.map((pt, i) => `${bytesToHex(xbytes(pt))} / ${bytesToHex(xbytes(honest2[i]))}`),
    attackerNonces: [bytesToHex(xbytes(attackerR1)), bytesToHex(xbytes(attackerR2))],
    attempts,
    b: bActual,
  };
}

/** A convenient, honestly-random target nonce for the exhibit. */
export function randomTargetNonce(): { point: Pt; secret: bigint; compressed: string } {
  const secret = randomScalar();
  const point = mul(G, secret);
  return { point, secret, compressed: bytesToHex(cbytes(point)) };
}
