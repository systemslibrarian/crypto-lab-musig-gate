/**
 * The rogue-key attack — a complete, real forgery, and the coefficient that kills it.
 *
 * THE ATTACK.  Honest signers publish P_1 … P_{u-1}. The attacker goes last and
 * publishes not a key it generated, but a key it *solved for*:
 *
 *     P_rogue = t·G − (P_1 + … + P_{u-1})       for a t the attacker picks
 *
 * Under naive aggregation the group's key is then
 *
 *     Q = ΣP_i = P_1 + … + P_{u-1} + P_rogue = t·G
 *
 * so the attacker knows Q's discrete log. It does not need the other signers, the
 * protocol, or a signing session: it signs alone with an ordinary BIP-340
 * signature under t, and every verifier on earth accepts. This is not a
 * theoretical weakness — it is one subtraction, and P_rogue is a perfectly
 * well-formed public key that no validity check can reject.
 *
 * THE DEFENCE.  BIP-327 aggregates as Q = Σ a_i·P_i with
 * a_i = H("KeyAgg coefficient", L ‖ P_i) and L = H("KeyAgg list", P_1 ‖ … ‖ P_u).
 * Now solving for a rogue key requires
 *
 *     P_rogue = a_rogue⁻¹ · (t·G − Σ_{i<u} a_i·P_i)
 *
 * where a_rogue = H(L ‖ P_rogue) and L itself hashes P_rogue. The attacker must
 * find a key that hashes to the coefficient that produces that very key — a hash
 * fixed point. `attemptBip327Rogue` runs the fixed-point iteration for real and
 * reports how far off it lands, then hands the resulting forgery to the genuine
 * verifier, which rejects it.
 *
 * Every function here operates on real secp256k1 points and real BIP-340
 * signatures. Nothing is mocked, and the verifier is the same one the honest
 * exhibits use.
 */
import {
  G,
  INFINITY,
  N,
  type Pt,
  add,
  bigTo32,
  bytesToHex,
  cbytes,
  concatBytes,
  cpoint,
  hasEvenY,
  hexToBytes,
  invN,
  mod,
  mul,
  negate,
  randomScalar,
  xbytes,
} from './field.js';
import { challenge, verify, type VerifyResult } from './bip340.js';
import { hashKeys, keyAgg, keyAggCoeffInternal, getSecondKey, type PlainPk } from './keyagg.js';
import { naiveKeyAgg } from './naive.js';

/**
 * Sign a message alone under the aggregate key, using a secret the attacker
 * believes is Q's discrete log. This is just plain BIP-340 single-signer signing —
 * the attacker is not running MuSig at all, which is exactly the point.
 */
export function soloSign(secret: bigint, msg: Uint8Array): { sig: Uint8Array; pubkeyX: Uint8Array } {
  const Ppt = mul(G, secret);
  const px = xbytes(Ppt);
  // Flip to the even-y representative, as BIP-340's x-only encoding requires.
  const d = hasEvenY(Ppt) ? mod(secret, N) : mod(N - secret, N);
  const k = randomScalar();
  const Rpt = mul(G, k);
  const kEff = hasEvenY(Rpt) ? k : N - k;
  const e = challenge(xbytes(Rpt), px, msg);
  const s = mod(kEff + e * d, N);
  return { sig: concatBytes(xbytes(Rpt), bigTo32(s)), pubkeyX: px };
}

export interface RogueKeyResult {
  /** The honest signers' plain public keys, in list order. */
  honestPubkeys: string[];
  /** The key the attacker solved for. */
  roguePubkey: string;
  /** The attacker's chosen discrete log for the target aggregate key. */
  attackerSecret: bigint;
  /** x-only aggregate key the group would publish. */
  aggregateKeyX: string;
  /** True when the attacker really does hold the aggregate key's discrete log. */
  attackerOwnsAggregate: boolean;
  /** The solo signature the attacker produced without the honest signers. */
  forgedSignature: string;
  /** The genuine BIP-340 verifier's verdict on that signature. */
  verdict: VerifyResult;
}

/**
 * NAIVE MODE: mount the attack and succeed.
 *
 * Returns a forgery that the real verifier ACCEPTS under the group's aggregate
 * key, produced without any honest signer's participation. A verifier has no way
 * to detect this — the signature is valid; the *key setup* was the vulnerability.
 */
export function naiveRogueAttack(honestSecrets: bigint[], msg: Uint8Array): RogueKeyResult {
  const honestPoints = honestSecrets.map((d) => mul(G, d));
  const honestPubkeys = honestPoints.map((pt) => cbytes(pt));

  // The attacker picks the discrete log it wants the group key to have...
  const t = randomScalar();
  // ...then subtracts the honest keys away.
  let sumHonest: Pt = INFINITY;
  for (const pt of honestPoints) sumHonest = add(sumHonest, pt);
  const roguePoint = add(mul(G, t), negate(sumHonest));
  if (roguePoint.is0()) throw new Error('degenerate rogue key (retry with a different t)');
  const roguePk = cbytes(roguePoint);

  const Q = naiveKeyAgg([...honestPubkeys, roguePk]);
  const attackerOwnsAggregate = Q.equals(mul(G, t));

  const { sig } = soloSign(t, msg);
  const verdict = verify(sig, msg, xbytes(Q));

  return {
    honestPubkeys: honestPubkeys.map(bytesToHex),
    roguePubkey: bytesToHex(roguePk),
    attackerSecret: t,
    aggregateKeyX: bytesToHex(xbytes(Q)),
    attackerOwnsAggregate,
    forgedSignature: bytesToHex(sig),
    verdict,
  };
}

/** One round of the attacker's fixed-point search under BIP-327 aggregation. */
export interface FixedPointRound {
  round: number;
  /** The candidate rogue key this round proposed. */
  candidate: string;
  /** The coefficient the candidate actually hashes to. */
  actualCoeff: bigint;
  /** x-only key the group would really end up with, given that candidate. */
  actualAggregateX: string;
  /** Whether that equals the attacker's target t·G. */
  hitTarget: boolean;
}

export interface Bip327RogueResult extends RogueKeyResult {
  /** The attacker's iteration log — it never converges. */
  rounds: FixedPointRound[];
  /** x-only key the attacker was aiming at. */
  targetKeyX: string;
}

/**
 * BIP-327 MODE: mount the same attack and fail.
 *
 * The attacker iterates the fixed point: guess a coefficient, solve for the key
 * that coefficient would need, hash that key to get the coefficient it *actually*
 * has, repeat. Each round the aggregate lands somewhere unrelated to the target.
 * We then hand the attacker's solo signature to the real verifier, which rejects
 * it, because the attacker does not know the aggregate key's discrete log.
 *
 * `rounds` is capped: the point is that iteration does not converge, not that we
 * can search forever. Convergence would require a preimage-style break of
 * SHA-256, and if it ever happened `hitTarget` would report it honestly.
 */
export function attemptBip327Rogue(
  honestSecrets: bigint[],
  msg: Uint8Array,
  maxRounds = 6,
): Bip327RogueResult {
  const honestPoints = honestSecrets.map((d) => mul(G, d));
  const honestPubkeys = honestPoints.map((pt) => cbytes(pt));
  const t = randomScalar();
  const targetPoint = mul(G, t);

  const rounds: FixedPointRound[] = [];
  // Seed the iteration with an arbitrary coefficient guess.
  let guessedCoeff = 1n;
  let candidatePk: PlainPk = cbytes(mul(G, randomScalar()));

  for (let round = 1; round <= maxRounds; round++) {
    // Solve  a_rogue·P_rogue = t·G − Σ a_i·P_i  for P_rogue, using the honest
    // coefficients implied by the CURRENT candidate list (they depend on it too).
    const keys = [...honestPubkeys, candidatePk];
    const L = hashKeys(keys);
    const pk2 = getSecondKey(keys);
    let weighted: Pt = INFINITY;
    for (let i = 0; i < honestPubkeys.length; i++) {
      weighted = add(weighted, mul(honestPoints[i], keyAggCoeffInternal(L, honestPubkeys[i], pk2)));
    }
    const needed = add(targetPoint, negate(weighted));
    const solved = mul(needed, invN(guessedCoeff));
    if (solved.is0()) {
      // Degenerate; perturb and continue rather than crash.
      candidatePk = cbytes(mul(G, randomScalar()));
      guessedCoeff = mod(guessedCoeff + 1n, N) || 1n;
      continue;
    }
    candidatePk = cbytes(solved);

    // Now find out what coefficient that key REALLY gets, and where Q really lands.
    const finalKeys = [...honestPubkeys, candidatePk];
    const actualCoeff = keyAggCoeffInternal(
      hashKeys(finalKeys),
      candidatePk,
      getSecondKey(finalKeys),
    );
    const actualQ = keyAgg(finalKeys).Q;
    rounds.push({
      round,
      candidate: bytesToHex(candidatePk),
      actualCoeff,
      actualAggregateX: bytesToHex(xbytes(actualQ)),
      hitTarget: actualQ.equals(targetPoint),
    });
    if (actualQ.equals(targetPoint)) break; // would mean SHA-256 is broken
    guessedCoeff = actualCoeff; // feed the real coefficient back in and try again
  }

  const finalKeys = [...honestPubkeys, candidatePk];
  const Q = keyAgg(finalKeys).Q;
  const { sig } = soloSign(t, msg);
  const verdict = verify(sig, msg, xbytes(Q));

  return {
    honestPubkeys: honestPubkeys.map(bytesToHex),
    roguePubkey: bytesToHex(candidatePk),
    attackerSecret: t,
    aggregateKeyX: bytesToHex(xbytes(Q)),
    attackerOwnsAggregate: Q.equals(targetPoint),
    forgedSignature: bytesToHex(sig),
    verdict,
    rounds,
    targetKeyX: bytesToHex(xbytes(targetPoint)),
  };
}

/**
 * Let the learner supply the rogue key directly (the "type your own attack" path).
 * Returns the honest verdict for whatever they hand in, under either aggregation
 * rule. Malformed keys throw — a rogue key still has to be a valid point.
 */
export function tryRogueKey(
  honestSecrets: bigint[],
  rogueKeyHex: string,
  attackerSecret: bigint,
  msg: Uint8Array,
  mode: 'naive' | 'bip327',
): RogueKeyResult {
  const honestPubkeys = honestSecrets.map((d) => cbytes(mul(G, d)));
  const roguePk = cbytes(cpoint(hexToBytes(rogueKeyHex)));
  const keys = [...honestPubkeys, roguePk];
  const Q = mode === 'naive' ? naiveKeyAgg(keys) : keyAgg(keys).Q;
  const { sig } = soloSign(attackerSecret, msg);
  return {
    honestPubkeys: honestPubkeys.map(bytesToHex),
    roguePubkey: bytesToHex(roguePk),
    attackerSecret,
    aggregateKeyX: bytesToHex(xbytes(Q)),
    attackerOwnsAggregate: Q.equals(mul(G, attackerSecret)),
    forgedSignature: bytesToHex(sig),
    verdict: verify(sig, msg, xbytes(Q)),
  };
}
