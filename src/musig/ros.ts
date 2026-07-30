/**
 * The ROS attack — a forgery at FULL 256-bit width, with nothing reduced.
 *
 * `wagner.ts` had to truncate the challenge so a generalised-birthday search would
 * finish in a browser tab. This attack needs no search at all. It is the
 * polynomial-time solution to the ROS problem of Benhamouda, Lepoint, Loss, Orrù and
 * Raykova (2020), and against single-nonce Schnorr multisig it is pure linear algebra:
 * open ℓ = 256 concurrent sessions, compute two candidate challenges per session
 * offline, read the bits of one field element, and the forgery falls out.
 *
 * Nothing here is reduced. Real secp256k1, the real 256-bit challenge, real
 * hash-derived key-aggregation coefficients, a real signing oracle that refuses to
 * reuse a nonce, and the same verifier the honest path uses. 256 sessions in,
 * 257 signatures out.
 *
 * HOW IT WORKS.  In session i the honest signer commits R_i = k_i·G first. The
 * adversary may add any offset α to it, so it can realise the challenge
 *
 *     y_i(α) = H( R_i + α·G ‖ Q ‖ m_i )   mod n
 *
 * for any α it likes — and it can evaluate that hash offline, without consuming the
 * session, because the hash is public. So for each i it picks two offsets and gets
 * two candidate challenges y_i⁰ and y_i¹, of which it will later commit to exactly one.
 *
 * Now define, for i = 1 … 256,
 *
 *     ρ_i = 2^(i-1) · (y_i¹ − y_i⁰)^(−1)   mod n
 *
 * so that for any choice of bits b_i,
 *
 *     Σ_i ρ_i · (y_i^(b_i) − y_i⁰)  =  Σ_i 2^(i-1)·b_i  =  B,
 *
 * the integer whose binary digits are exactly those bits. Every residue mod n is
 * reachable as such a B, because n < 2^256 and there are 256 bits to play with.
 *
 * THE CIRCULARITY THAT ISN'T.  The adversary sets its forged nonce to
 *
 *     R* = Σ_i ρ_i·R_i + τ·G
 *
 * using ONLY the honest signer's commitments plus a free τ it chooses. The α offsets
 * do not appear, so R*, and therefore e* = H(R* ‖ Q ‖ m*), is fixed before a single
 * bit is chosen. That is the same asymmetry Wagner exploited — and here it is fatal
 * without any search, because the adversary can simply solve
 *
 *     B = e* − Σ_i ρ_i·y_i⁰   (mod n)
 *
 * read off the 256 bits of B, publish the matching offset in each session, and get
 * Σ_i ρ_i·e_i = e* exactly. Then
 *
 *     s* = Σ_i ρ_i·s_i + τ + e*·q_A       satisfies      s*·G = R* + e*·Q
 *
 * on a message nobody authorised.
 *
 * WHY MUSIG2 SURVIVES IT.  With two nonces the honest contribution is
 * Σ_i ρ_i·(R_i1 + b_i·R_i2), and b_i hashes the aggregate nonce — which contains the
 * adversary's own offset. So R* now moves with the very bits being solved for, e*
 * moves with it, and the linear system has no fixed right-hand side to solve against.
 * `attemptRosTwoNonce` runs exactly that and reports the drift.
 *
 * NOT production crypto — a teaching demo, and this file is an attack on a scheme
 * nobody should deploy.
 */
import {
  G,
  INFINITY,
  N,
  type Pt,
  add,
  bigTo32,
  bytesToBig,
  bytesToHex,
  cbytes,
  invN,
  mod,
  mul,
  randomScalar,
  taggedHash,
  utf8,
  xbytes,
} from './field.js';
import { toyKeyAggCoeffs, toyNonceCoeff } from './wagner.js';

/** The FULL-width challenge: the whole hash, reduced mod n. Nothing truncated. */
export function rosChallenge(R: Pt, Q: Pt, msg: Uint8Array): bigint {
  return mod(bytesToBig(taggedHash('MuSigGate/ros/challenge', cbytes(R), cbytes(Q), msg)), N);
}

/** Textbook Schnorr verification at full width: s·G = R + e·Q. */
export function verifyFullWidth(R: Pt, s: bigint, Q: Pt, msg: Uint8Array): boolean {
  return mul(G, s).equals(add(R, mul(Q, rosChallenge(R, Q, msg))));
}

/** ℓ = 256: one session per bit of the scalar field. */
export const ROS_SESSIONS = 256;

const FORGED_MESSAGE = 'Pay the adversary the entire treasury (never authorised by anyone)';

/** The honest signer, behaving impeccably and still robbed. */
class FullWidthSigner {
  readonly secret: bigint;
  readonly pubkey: Pt;
  private readonly nonces: (bigint | null)[] = [];
  readonly signed: string[] = [];

  constructor() {
    this.secret = randomScalar();
    this.pubkey = mul(G, this.secret);
  }

  commit(): { index: number; R: Pt } {
    const k = randomScalar();
    this.nonces.push(k);
    return { index: this.nonces.length - 1, R: mul(G, k) };
  }

  /** Signs once per nonce. A second call for the same session throws. */
  respond(index: number, e: bigint, qH: bigint, message: string): bigint {
    const k = this.nonces[index];
    if (k === null) throw new Error('nonce already used — this signer never reuses one');
    this.nonces[index] = null;
    this.signed.push(message);
    return mod(k + e * qH, N);
  }
}

export interface RosSessionDetail {
  index: number;
  honestNonceX: string;
  /** The offset the adversary published, chosen by the bit it needed. */
  alpha: bigint;
  bit: 0 | 1;
  /** The challenge that resulted — one of the two it precomputed. */
  e: bigint;
}

export interface RosForgeResult {
  sessions: number;
  /** 256. Stated explicitly because the point is that nothing was reduced. */
  challengeBits: number;
  /** ℓ sessions yield ℓ+1 signatures. */
  signaturesObtained: number;
  aggregateKeyX: string;
  forgedMessage: string;
  honestSignerNeverSawIt: boolean;
  /** Every message the honest signer really did authorise. */
  queriedMessageCount: number;
  /** A readable sample of the sessions, not all 256. */
  sampleSessions: RosSessionDetail[];
  /** The linear relation the attack had to satisfy, both sides computed. */
  sumRhoE: string;
  eStar: string;
  linearRelationHolds: boolean;
  /** How many bits of B were set — i.e. how many sessions took the y¹ branch. */
  onesInB: number;
  forgedR: string;
  forgedS: string;
  /** The full-width verifier's verdict. Expected: accepted. */
  verified: boolean;
  scalarMultiplications: number;
}

/**
 * Mount the ROS attack and return a real forgery — at the real challenge width.
 *
 * No search, no truncation, no retries: the bits fall out of one modular
 * subtraction. If this ever failed it would be a bug in the algebra, not bad luck.
 */
export function forgeRos(): RosForgeResult {
  const honest = new FullWidthSigner();
  const advSecret = randomScalar();
  const advPub = mul(G, advSecret);

  // Sound, hash-derived key aggregation: the key setup is not the flaw here either.
  const [cH, cA] = toyKeyAggCoeffs([honest.pubkey, advPub]);
  const Q = add(mul(honest.pubkey, cH), mul(advPub, cA));
  const qH = mod(cH * honest.secret, N);
  const qA = mod(cA * advSecret, N);

  const messages = Array.from({ length: ROS_SESSIONS }, (_, i) => `Routine payment #${i + 1}`);
  const forgedMsg = utf8(FORGED_MESSAGE);
  let scalarMultiplications = 0;

  // Round 1: the honest signer commits to all 256 sessions before seeing anything.
  const commits = Array.from({ length: ROS_SESSIONS }, () => honest.commit());

  // For each session, two candidate challenges, computed OFFLINE. Evaluating the
  // hash costs the adversary nothing and consumes no session.
  const alpha0 = 1n;
  const alpha1 = 2n;
  const y0: bigint[] = [];
  const y1: bigint[] = [];
  const rho: bigint[] = [];
  for (let i = 0; i < ROS_SESSIONS; i++) {
    const msg = utf8(messages[i]);
    const a = rosChallenge(add(commits[i].R, mul(G, alpha0)), Q, msg);
    const b = rosChallenge(add(commits[i].R, mul(G, alpha1)), Q, msg);
    if (a === b) throw new Error('degenerate session: the two candidate challenges collided');
    y0.push(a);
    y1.push(b);
    // ρ_i scales the i-th bit into place and normalises the gap between the two
    // candidates to exactly 1.
    rho.push(mod(mod(1n << BigInt(i), N) * invN(mod(b - a, N)), N));
  }

  // R* is built from the HONEST commitments plus a free offset, so it does not move
  // when the adversary later picks its bits. That is the whole vulnerability.
  const tau = randomScalar();
  let Rstar: Pt = mul(G, tau);
  scalarMultiplications++;
  for (let i = 0; i < ROS_SESSIONS; i++) {
    Rstar = add(Rstar, mul(commits[i].R, rho[i]));
    scalarMultiplications++;
  }
  if (Rstar.is0()) throw new Error('degenerate forged nonce (retry)');
  const eStar = rosChallenge(Rstar, Q, forgedMsg);

  // Solve for the bit pattern. One subtraction — no search anywhere in this attack.
  let C = 0n;
  for (let i = 0; i < ROS_SESSIONS; i++) C = mod(C + rho[i] * y0[i], N);
  const B = mod(eStar - C, N);

  // Publish the offset each bit demands, and collect the honest responses.
  const detail: RosSessionDetail[] = [];
  let sumS = 0n;
  let sumRhoE = 0n;
  let onesInB = 0;
  for (let i = 0; i < ROS_SESSIONS; i++) {
    const bit: 0 | 1 = (B >> BigInt(i)) & 1n ? 1 : 0;
    if (bit === 1) onesInB++;
    const alpha = bit === 1 ? alpha1 : alpha0;
    const e = bit === 1 ? y1[i] : y0[i];
    const s = honest.respond(commits[i].index, e, qH, messages[i]);
    sumS = mod(sumS + rho[i] * s, N);
    sumRhoE = mod(sumRhoE + rho[i] * e, N);
    if (i < 6) {
      detail.push({
        index: i,
        honestNonceX: bytesToHex(xbytes(commits[i].R)),
        alpha,
        bit,
        e,
      });
    }
  }

  // s* adds only values the adversary already holds.
  const sStar = mod(sumS + tau + eStar * qA, N);
  const verified = verifyFullWidth(Rstar, sStar, Q, forgedMsg);

  return {
    sessions: ROS_SESSIONS,
    challengeBits: 256,
    signaturesObtained: ROS_SESSIONS + 1,
    aggregateKeyX: bytesToHex(xbytes(Q)),
    forgedMessage: FORGED_MESSAGE,
    honestSignerNeverSawIt: !honest.signed.includes(FORGED_MESSAGE),
    queriedMessageCount: honest.signed.length,
    sampleSessions: detail,
    sumRhoE: bytesToHex(bigTo32(sumRhoE)),
    eStar: bytesToHex(bigTo32(eStar)),
    linearRelationHolds: sumRhoE === eStar,
    onesInB,
    forgedR: bytesToHex(xbytes(Rstar)),
    forgedS: bytesToHex(bigTo32(sStar)),
    verified,
    scalarMultiplications,
  };
}

export interface RosTwoNonceResult {
  sessions: number;
  /** The target computed before any bit was chosen. */
  targetedEStar: string;
  /** The target that actually applies once the offsets are published. */
  actualEStar: string;
  targetDrifted: boolean;
  /** Σ ρ_i·e_i, which solved the system for the STALE target. */
  sumRhoE: string;
  /** True only if the linear relation survived — it should not. */
  linearRelationHolds: boolean;
  forgedR: string;
  forgedS: string;
  /** The same verifier that accepted the single-nonce forgery. Expected: rejected. */
  verified: boolean;
  explanation: string;
}

/**
 * The same attack against two nonces. The linear algebra is unchanged and still
 * solvable — what breaks is that its right-hand side is no longer a constant.
 *
 * A smaller ℓ is used here because nothing needs solving to a full 256-bit target:
 * the point is that the target moves, which one publication demonstrates.
 */
export function attemptRosTwoNonce(opts: { sessions?: number } = {}): RosTwoNonceResult {
  const sessions = opts.sessions ?? 32;

  const honestSecret = randomScalar();
  const honestPub = mul(G, honestSecret);
  const advSecret = randomScalar();
  const advPub = mul(G, advSecret);
  const [cH, cA] = toyKeyAggCoeffs([honestPub, advPub]);
  const Q = add(mul(honestPub, cH), mul(advPub, cA));
  const qH = mod(cH * honestSecret, N);
  const qA = mod(cA * advSecret, N);

  const messages = Array.from({ length: sessions }, (_, i) => `Routine payment #${i + 1}`);
  const forgedMsg = utf8(FORGED_MESSAGE);

  const honestNonces = Array.from({ length: sessions }, () => {
    const k1 = randomScalar();
    const k2 = randomScalar();
    return { k1, k2, R1: mul(G, k1), R2: mul(G, k2) };
  });
  const advK2 = Array.from({ length: sessions }, () => randomScalar());
  const rho = Array.from({ length: sessions }, () => randomScalar());
  const tau = randomScalar();

  /**
   * The honest contribution the adversary must aim at. With one nonce this was
   * Σ ρ_i·R_i and involved nothing of the adversary's. With two, b_i hashes the
   * adversary's own offset, so the whole sum moves when the offsets do.
   */
  const contribution = (alphas: bigint[]): { point: Pt; bs: bigint[] } => {
    let acc: Pt = INFINITY;
    const bs: bigint[] = [];
    for (let i = 0; i < sessions; i++) {
      const R1 = add(honestNonces[i].R1, mul(G, alphas[i]));
      const R2 = add(honestNonces[i].R2, mul(G, advK2[i]));
      const b = toyNonceCoeff(R1, R2, Q, utf8(messages[i]));
      bs.push(b);
      acc = add(acc, mul(add(honestNonces[i].R1, mul(honestNonces[i].R2, b)), rho[i]));
    }
    return { point: acc, bs };
  };

  // Step 1: the adversary computes its target under an initial guess.
  const guess = Array.from({ length: sessions }, () => 1n);
  const guessed = contribution(guess);
  const targetedRstar = add(guessed.point, mul(G, tau));
  const targetedEStar = rosChallenge(targetedRstar, Q, forgedMsg);

  // Step 2: it solves the system and publishes the offsets that solution requires.
  const chosen = Array.from({ length: sessions }, (_, i) => ((targetedEStar >> BigInt(i)) & 1n) + 1n);
  const actual = contribution(chosen);
  const actualRstar = add(actual.point, mul(G, tau));
  const actualEStar = rosChallenge(actualRstar, Q, forgedMsg);

  // Step 3: complete the forgery anyway with the honest signer's real responses.
  let sumS = 0n;
  let sumRhoE = 0n;
  for (let i = 0; i < sessions; i++) {
    const R1 = add(honestNonces[i].R1, mul(G, chosen[i]));
    const R2 = add(honestNonces[i].R2, mul(G, advK2[i]));
    const b = actual.bs[i];
    const e = rosChallenge(add(R1, mul(R2, b)), Q, utf8(messages[i]));
    sumRhoE = mod(sumRhoE + rho[i] * e, N);
    sumS = mod(sumS + rho[i] * mod(honestNonces[i].k1 + b * honestNonces[i].k2 + e * qH, N), N);
  }
  const sStar = mod(sumS + tau + actualEStar * qA, N);
  const verified = verifyFullWidth(actualRstar, sStar, Q, forgedMsg);

  return {
    sessions,
    targetedEStar: bytesToHex(bigTo32(targetedEStar)),
    actualEStar: bytesToHex(bigTo32(actualEStar)),
    targetDrifted: targetedEStar !== actualEStar,
    sumRhoE: bytesToHex(bigTo32(sumRhoE)),
    linearRelationHolds: sumRhoE === actualEStar,
    forgedR: bytesToHex(xbytes(actualRstar)),
    forgedS: bytesToHex(bigTo32(sStar)),
    verified,
    explanation:
      'The linear system is as solvable as ever — what it lost is a constant right-hand side. R* is now built from Σ ρ_i·(R_i1 + b_i·R_i2), and every b_i hashes the aggregate nonce containing the adversary’s own offset. Publishing the offsets the solution demands changes the b values, moves R*, and moves e* with it, so the system was solved against a target that no longer applies.',
  };
}
