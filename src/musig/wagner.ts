/**
 * Wagner's k-list attack, run for real — the forgery that killed single-nonce
 * two-round Schnorr multisig, and the exact reason MuSig2's second nonce stops it.
 *
 * `noncecontrol.ts` shows the *capability*: with one nonce per signer, whoever
 * publishes last controls the aggregate nonce. This module closes the gap and
 * produces an actual forged signature — a valid signature on a message the honest
 * signer never agreed to sign — using Wagner's generalised-birthday algorithm over
 * k concurrent signing sessions (Drijvers et al., "On the Security of Two-Round
 * Multi-Signatures", IEEE S&P 2019).
 *
 * WHAT IS REAL HERE, AND WHAT IS REDUCED.  Everything is real secp256k1: real keys,
 * real point arithmetic, real hash-derived key-aggregation coefficients (so the key
 * setup is NOT the flaw — this is purely about nonces), a real signing oracle, and a
 * real verifier that the forgery is handed to. Exactly ONE parameter is reduced: the
 * challenge is truncated to `bits` bits instead of 256, so the birthday search fits
 * in a browser tab. Wagner's algorithm is unmodified. At the full 256 bits the same
 * algorithm needs about 2^(256/(1+log2 k)) work — for k = 4, roughly 2^85 — which is
 * why this is a devastating break in theory and not something you watch happen.
 *
 * THE ALGEBRA.  Two signers, adversary is signer A, honest signer is H.
 *
 *   Q  = c_H·P_H + c_A·P_A          the aggregate key   (q_H = c_H·x, q_A = c_A·a)
 *
 * In session j the honest signer commits R_H^(j) = k_j·G FIRST. The adversary then
 * picks its own nonce ρ_j·G, so the session nonce and challenge are
 *
 *   R^(j) = R_H^(j) + ρ_j·G         e_j = trunc_b( H( R^(j) ‖ Q ‖ m_j ) )
 *
 * and the honest signer returns  s_H^(j) = k_j + e_j·q_H.  Summing k of those:
 *
 *   Σ s_H^(j) = Σ k_j + (Σ e_j)·q_H          and      (Σ k_j)·G = Σ R_H^(j)
 *
 * THE ASYMMETRY THAT IS THE WHOLE LESSON.  Σ R_H^(j) does not depend on the
 * adversary's nonces at all. So the adversary can fix its forged nonce
 * R* = Σ R_H^(j) + ρ*·G and its target challenge e* = trunc_b(H(R* ‖ Q ‖ m*))
 * BEFORE it starts grinding — then hunt for ρ_1…ρ_k with Σ e_j = e*. That is a
 * k-sum problem, which is exactly what Wagner's algorithm solves. Given a solution,
 *
 *   s* = Σ s_H^(j) + ρ* + e*·q_A     satisfies     s*·G = R* + e*·Q
 *
 * and (R*, s*) is a valid signature on m*, which nobody ever authorised.
 *
 * WHY MUSIG2 SURVIVES IT.  With two nonces the honest contribution the adversary
 * must aim at is Σ_j (R_H1^(j) + b_j·R_H2^(j)), and b_j = H(aggnonce ‖ Q ‖ m_j)
 * depends on the adversary's OWN nonces. So the moment it grinds ρ_j to move e_j,
 * b_j moves, the honest contribution moves, R* moves, and e* moves with it. The
 * target is no longer fixed, the k lists are no longer independent, and Wagner's
 * k-tree has nothing to bite on. `attemptTwoNonceForgery` runs precisely that and
 * reports how far the target drifted.
 *
 * NOT production crypto — a teaching demo, and this file in particular is an attack
 * on a scheme nobody should deploy.
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
  concatBytes,
  mod,
  mul,
  randomScalar,
  taggedHash,
  utf8,
  xbytes,
} from './field.js';

/** The toy scheme's reduced challenge: the full hash, truncated to `bits` bits. */
export function truncChallenge(bits: number, R: Pt, Q: Pt, msg: Uint8Array): bigint {
  const full = bytesToBig(taggedHash('MuSigGate/wagner/challenge', cbytes(R), cbytes(Q), msg));
  return full & ((1n << BigInt(bits)) - 1n);
}

/** The nonce coefficient b, for the two-nonce comparison. Full width, not truncated. */
export function toyNonceCoeff(R1: Pt, R2: Pt, Q: Pt, msg: Uint8Array): bigint {
  return mod(
    bytesToBig(taggedHash('MuSigGate/wagner/noncecoef', cbytes(R1), cbytes(R2), cbytes(Q), msg)),
    N,
  );
}

/**
 * Hash-derived key-aggregation coefficients, same construction as BIP-327.
 * Present so that nobody can claim this attack is really the rogue-key attack in
 * disguise: the key setup here is sound, and the forgery still goes through.
 */
export function toyKeyAggCoeffs(pubkeys: Pt[]): bigint[] {
  const list = concatBytes(...pubkeys.map(cbytes));
  return pubkeys.map((P) =>
    mod(bytesToBig(taggedHash('MuSigGate/wagner/keyagg', list, cbytes(P))), N),
  );
}

/** A textbook Schnorr verifier for the toy scheme: s·G = R + e·Q, e truncated. */
export function verifyToy(bits: number, R: Pt, s: bigint, Q: Pt, msg: Uint8Array): boolean {
  const e = truncChallenge(bits, R, Q, msg);
  return mul(G, s).equals(add(R, mul(Q, e)));
}

// ------------------------------------------------------------------ Wagner k-tree

interface ListEntry {
  /** The challenge value this list element realises. */
  e: bigint;
  /** The adversary nonce offset that produced it. */
  rho: bigint;
}

interface JoinEntry {
  /** The true integer sum of this half's challenge values — never reduced. */
  exact: bigint;
  /** The same sum modulo 2^bits, used only for bucketing. */
  masked: bigint;
  rhos: bigint[];
}

/**
 * Wagner's k-tree for k = 4, over the additive group of integers mod 2^bits.
 *
 * Find one element from each of the four lists whose challenge values sum to
 * `target`. The tree joins pairs on their low `joinBits` bits so the surviving
 * partial sums are already partly aligned, then matches the two halves on the
 * remaining bits. That is the whole trick: it turns a 2^bits search into roughly
 * 2^(bits/3) work.
 *
 * Only solutions whose values sum to `target` as INTEGERS are returned. A match
 * modulo 2^bits can be off by a multiple of 2^bits, and such a solution is useless
 * here because the algebra needs equality of scalars, not of low bits — so those are
 * filtered out rather than reported as successes.
 */
export function wagnerFourSum(
  lists: ListEntry[][],
  target: bigint,
  bits: number,
): { rhos: bigint[]; candidatesModular: number; candidatesExact: number } | null {
  if (lists.length !== 4) throw new Error('this k-tree is written for exactly 4 lists');
  const joinBits = Math.ceil(bits / 3);
  const joinMask = (1n << BigInt(joinBits)) - 1n;
  const fullMask = (1n << BigInt(bits)) - 1n;

  /** Join two lists, keeping pairs whose low `joinBits` bits hit `residue`. */
  const join = (a: ListEntry[], b: ListEntry[], residue: bigint): JoinEntry[] => {
    const buckets = new Map<string, ListEntry[]>();
    for (const y of b) {
      const key = String((residue - y.e) & joinMask);
      const slot = buckets.get(key);
      if (slot) slot.push(y);
      else buckets.set(key, [y]);
    }
    const out: JoinEntry[] = [];
    for (const x of a) {
      const hits = buckets.get(String(x.e & joinMask));
      if (!hits) continue;
      for (const y of hits) {
        const exact = x.e + y.e;
        out.push({ exact, masked: exact & fullMask, rhos: [x.rho, y.rho] });
      }
    }
    return out;
  };

  // Left half aims at 0 on the low bits; right half aims at the target's low bits.
  // Their sum then already agrees with the target on those bits by construction.
  const left = join(lists[0], lists[1], 0n);
  const right = join(lists[2], lists[3], target & joinMask);

  const rightBuckets = new Map<string, JoinEntry[]>();
  for (const y of right) {
    const key = String((target - y.masked) & fullMask);
    const slot = rightBuckets.get(key);
    if (slot) slot.push(y);
    else rightBuckets.set(key, [y]);
  }

  let candidatesModular = 0;
  let candidatesExact = 0;
  let solution: bigint[] | null = null;
  for (const x of left) {
    const hits = rightBuckets.get(String(x.masked));
    if (!hits) continue;
    for (const y of hits) {
      candidatesModular++;
      // The filter that matters: the four challenge values must sum to the target as
      // INTEGERS. A match modulo 2^bits can be off by a multiple of 2^bits, and such
      // a solution is algebraically useless here, so it is discarded rather than
      // reported as a hit.
      if (x.exact + y.exact !== target) continue;
      candidatesExact++;
      if (!solution) solution = [...x.rhos, ...y.rhos];
    }
  }
  return solution ? { rhos: solution, candidatesModular, candidatesExact } : null;
}

// --------------------------------------------------------------- the honest signer

/**
 * The honest signer in the BROKEN single-nonce scheme. It behaves impeccably: one
 * fresh nonce per session, committed before it sees the adversary's, and it only
 * ever signs the message it was asked about. It is still robbed.
 */
class SingleNonceSigner {
  readonly secret: bigint;
  readonly pubkey: Pt;
  private readonly nonces: (bigint | null)[] = [];
  /** Every message this signer actually agreed to sign. */
  readonly signed: string[] = [];

  constructor() {
    this.secret = randomScalar();
    this.pubkey = mul(G, this.secret);
  }

  /** Round 1: commit a nonce, before knowing the adversary's. */
  commit(): { index: number; R: Pt } {
    const k = randomScalar();
    this.nonces.push(k);
    return { index: this.nonces.length - 1, R: mul(G, k) };
  }

  /**
   * Round 2: sign whatever aggregate nonce resulted, exactly once per nonce.
   *
   * The single-use check matters for the integrity of the demonstration: nonce
   * REUSE leaks a private key outright and would forge signatures trivially, which
   * is a different attack. This signer never reuses one, so the forgery below can
   * only be coming from the k-sum.
   */
  respond(index: number, e: bigint, qH: bigint, message: string): bigint {
    const k = this.nonces[index];
    if (k === null) throw new Error('nonce already used — this signer never reuses one');
    this.nonces[index] = null;
    this.signed.push(message);
    return mod(k + e * qH, N);
  }
}

// -------------------------------------------------------------------- the forgery

export interface WagnerSession {
  message: string;
  honestNonceX: string;
  /** The adversary's nonce offset, found by the k-sum search. */
  rho: bigint;
  aggregateNonceX: string;
  e: bigint;
  honestPartial: bigint;
}

export interface WagnerForgeResult {
  bits: number;
  sessions: number;
  listSize: number;
  joinBits: number;
  /** Point additions plus hashes spent building the lists. */
  listOps: number;
  attempts: number;
  candidatesModular: number;
  candidatesExact: number;

  aggregateKeyX: string;
  /** The messages the honest signer really did authorise. */
  queriedMessages: string[];
  /** The message it never saw, and now has a valid signature on. */
  forgedMessage: string;

  sessionDetail: WagnerSession[];
  eStar: bigint;
  sumOfChallenges: bigint;
  /** True when Σ e_j equals e* as integers — required, and checked. */
  exactSum: boolean;

  forgedR: string;
  forgedS: string;
  /** The toy verifier's verdict on the forgery. Expected: accepted. */
  verified: boolean;
  /** Sanity: the honest signer never signed the forged message. */
  honestSignerNeverSawIt: boolean;
  /** Honest statement of what this costs at full width. */
  workAtFullWidth: string;
}

const FORGED_MESSAGE = 'Pay the adversary 100 BTC (never authorised by anyone)';

/**
 * Mount the attack against the single-nonce scheme and return a real forgery.
 *
 * `bits` is the only reduced parameter. `listBits` sets the per-list size; the
 * defaults are chosen so the search reliably succeeds in well under a second.
 */
export function forgeSingleNonce(
  opts: { bits?: number; listBits?: number; maxAttempts?: number } = {},
): WagnerForgeResult {
  const bits = opts.bits ?? 27;
  const listBits = opts.listBits ?? 11;
  const maxAttempts = opts.maxAttempts ?? 12;
  const sessions = 4; // the k in "k-list"
  const listSize = 1 << listBits;
  const joinBits = Math.ceil(bits / 3);

  const honest = new SingleNonceSigner();
  const advSecret = randomScalar();
  const advPub = mul(G, advSecret);

  // Sound, hash-derived key aggregation — the flaw here is nonces, not keys.
  const [cH, cA] = toyKeyAggCoeffs([honest.pubkey, advPub]);
  const Q = add(mul(honest.pubkey, cH), mul(advPub, cA));
  const qH = mod(cH * honest.secret, N);
  const qA = mod(cA * advSecret, N);

  const messages = Array.from({ length: sessions }, (_, j) => `Routine payment #${j + 1}`);
  const forgedMsg = utf8(FORGED_MESSAGE);

  // Round 1: the honest signer commits first, in all four sessions at once. This is
  // the concurrency the attack needs, and a signer has no way to detect it.
  const commits = Array.from({ length: sessions }, () => honest.commit());
  let honestSum: Pt = INFINITY;
  for (const c of commits) honestSum = add(honestSum, c.R);

  // Build one list per session by walking ρ = 1, 2, 3, … Each step is a single point
  // addition rather than a fresh scalar multiplication. The lists depend only on the
  // honest signer's commitments, so they are built ONCE and reused across attempts.
  let listOps = 0;
  const lists: ListEntry[][] = commits.map((commit, j) => {
    const msg = utf8(messages[j]);
    const entries: ListEntry[] = [];
    let R = commit.R;
    for (let rho = 1n; rho <= BigInt(listSize); rho++) {
      R = add(R, G);
      entries.push({ e: truncChallenge(bits, R, Q, msg), rho });
      listOps++;
    }
    return entries;
  });

  let attempts = 0;
  let candidatesModular = 0;
  let candidatesExact = 0;

  for (attempts = 1; attempts <= maxAttempts; attempts++) {
    // The adversary's own nonce for the forged signature. Because the honest
    // contribution above is already fixed, R* and e* are fixed too — before any
    // grinding happens. That is the whole vulnerability. Only e* varies per attempt,
    // so a retry is a fresh target against the same lists.
    const rhoStar = randomScalar();
    const Rstar = add(honestSum, mul(G, rhoStar));
    const eStar = truncChallenge(bits, Rstar, Q, forgedMsg);

    const found = wagnerFourSum(lists, eStar, bits);
    candidatesModular += found?.candidatesModular ?? 0;
    candidatesExact += found?.candidatesExact ?? 0;
    if (!found) continue;

    // Only now, with an exact solution in hand, are the sessions instantiated for
    // real — so each honest nonce is used exactly once, as its single-use check
    // enforces.
    const detail: WagnerSession[] = [];
    let sumS = 0n;
    let sumE = 0n;
    for (let j = 0; j < sessions; j++) {
      const rho = found.rhos[j];
      const Ragg = add(commits[j].R, mul(G, rho));
      const msg = utf8(messages[j]);
      const e = truncChallenge(bits, Ragg, Q, msg);
      const partial = honest.respond(commits[j].index, e, qH, messages[j]);
      sumS = mod(sumS + partial, N);
      sumE += e; // integer sum, deliberately not reduced
      detail.push({
        message: messages[j],
        honestNonceX: bytesToHex(xbytes(commits[j].R)),
        rho,
        aggregateNonceX: bytesToHex(xbytes(Ragg)),
        e,
        honestPartial: partial,
      });
    }

    if (sumE !== eStar) {
      throw new Error('internal error: the k-tree returned a non-exact solution');
    }

    // Assemble the forgery. The adversary adds only things it already knows.
    const sStar = mod(sumS + rhoStar + eStar * qA, N);
    const verified = verifyToy(bits, Rstar, sStar, Q, forgedMsg);

    return {
      bits,
      sessions,
      listSize,
      joinBits,
      listOps,
      attempts,
      candidatesModular,
      candidatesExact,
      aggregateKeyX: bytesToHex(xbytes(Q)),
      queriedMessages: [...honest.signed],
      forgedMessage: FORGED_MESSAGE,
      sessionDetail: detail,
      eStar,
      sumOfChallenges: sumE,
      exactSum: true,
      forgedR: bytesToHex(xbytes(Rstar)),
      forgedS: bytesToHex(bigTo32(sStar)),
      verified,
      honestSignerNeverSawIt: !honest.signed.includes(FORGED_MESSAGE),
      workAtFullWidth: fullWidthCost(sessions),
    };
  }

  throw new Error(
    `the k-sum search did not land an exact match in ${maxAttempts} attempts — raise listBits or lower bits`,
  );
}

// ------------------------------------------------- the same attack against MuSig2

export interface TwoNonceProbe {
  label: string;
  /** The adversary nonce offsets this probe published. */
  rhos: bigint[];
  /** The per-session nonce coefficients they produced. */
  bs: bigint[];
  /** The target challenge that results — different every time. */
  eStar: bigint;
}

export interface TwoNonceAttemptResult {
  bits: number;
  sessions: number;
  /** One row per candidate nonce assignment the adversary might publish. */
  probes: TwoNonceProbe[];
  /** How many distinct targets those assignments produced. */
  distinctTargets: number;
  /** True when the target is not fixed — the condition Wagner's k-tree requires. */
  targetDrifted: boolean;
  /** The target the adversary would have solved its k-sum against. */
  targetedEStar: bigint;
  /** The target that actually applies once it publishes the nonces it chose. */
  actualEStar: bigint;
  sumOfChallenges: bigint;
  aggregateKeyX: string;
  forgedR: string;
  forgedS: string;
  /** The verifier's verdict on the completed attempt. Expected: rejected. */
  verified: boolean;
  explanation: string;
}

/**
 * Run the identical attack against the two-nonce construction and show why it dies.
 *
 * Wagner's k-tree needs a FIXED target: you cannot build four independent lists and
 * search them for a sum unless you know what sum you are looking for. In the
 * single-nonce scheme that target is fixed before any grinding, because the honest
 * contribution Σ R_H^(j) does not involve the adversary's nonces at all.
 *
 * Here it does. The honest contribution is Σ (R_H1^(j) + b_j·R_H2^(j)), and
 * b_j = H(aggnonce ‖ Q ‖ m_j) hashes the adversary's own nonce. So this function does
 * not pretend to run a k-sum that cannot exist — it probes several candidate nonce
 * assignments and shows that each one produces a DIFFERENT target. That is the
 * precondition failing, demonstrated rather than asserted. It then completes one
 * forgery attempt anyway and hands it to the same verifier, which rejects it.
 */
export function attemptTwoNonceForgery(opts: { bits?: number; probes?: number } = {}): TwoNonceAttemptResult {
  const bits = opts.bits ?? 27;
  const probeCount = Math.max(2, opts.probes ?? 5);
  const sessions = 4;

  const honestSecret = randomScalar();
  const honestPub = mul(G, honestSecret);
  const advSecret = randomScalar();
  const advPub = mul(G, advSecret);
  const [cH, cA] = toyKeyAggCoeffs([honestPub, advPub]);
  const Q = add(mul(honestPub, cH), mul(advPub, cA));
  const qH = mod(cH * honestSecret, N);
  const qA = mod(cA * advSecret, N);

  const messages = Array.from({ length: sessions }, (_, j) => `Routine payment #${j + 1}`);
  const forgedMsg = utf8(FORGED_MESSAGE);

  // Round 1: the honest signer commits TWO nonces per session, before seeing any of
  // the adversary's.
  const honestNonces = Array.from({ length: sessions }, () => {
    const k1 = randomScalar();
    const k2 = randomScalar();
    return { k1, k2, R1: mul(G, k1), R2: mul(G, k2) };
  });
  const advK2 = Array.from({ length: sessions }, () => randomScalar());
  const rhoStar = randomScalar();

  /**
   * Everything downstream of one candidate nonce assignment: the b coefficients it
   * induces, the honest contribution the adversary must aim at, and the resulting
   * target challenge.
   */
  const evaluate = (rhos: bigint[]): { bs: bigint[]; Rstar: Pt; eStar: bigint; es: bigint[] } => {
    let honestPart: Pt = INFINITY;
    const bs: bigint[] = [];
    const es: bigint[] = [];
    for (let j = 0; j < sessions; j++) {
      const R1 = add(honestNonces[j].R1, mul(G, rhos[j]));
      const R2 = add(honestNonces[j].R2, mul(G, advK2[j]));
      const b = toyNonceCoeff(R1, R2, Q, utf8(messages[j]));
      bs.push(b);
      // What the adversary can aim at: only the honest signer's own contribution.
      honestPart = add(honestPart, add(honestNonces[j].R1, mul(honestNonces[j].R2, b)));
      es.push(truncChallenge(bits, add(R1, mul(R2, b)), Q, utf8(messages[j])));
    }
    const Rstar = add(honestPart, mul(G, rhoStar));
    return { bs, Rstar, eStar: truncChallenge(bits, Rstar, Q, forgedMsg), es };
  };

  // Probe candidate assignments. The first is the adversary's starting guess; the
  // rest are the sort of small perturbations grinding would walk through.
  const probes: TwoNonceProbe[] = [];
  const assignments: bigint[][] = [Array.from({ length: sessions }, () => 0n)];
  for (let i = 1; i < probeCount; i++) {
    assignments.push(Array.from({ length: sessions }, () => BigInt(i)));
  }
  for (let i = 0; i < assignments.length; i++) {
    const ev = evaluate(assignments[i]);
    probes.push({
      label: i === 0 ? 'starting guess (ρ = 0)' : `after grinding to ρ = ${assignments[i][0]}`,
      rhos: assignments[i],
      bs: ev.bs,
      eStar: ev.eStar,
    });
  }
  const distinctTargets = new Set(probes.map((p) => String(p.eStar))).size;

  // The adversary solves its k-sum against the target it saw first, then publishes
  // the nonces that solution requires — landing it in a different world.
  const targeted = probes[0];
  const realised = evaluate(assignments[1]);
  let sumS = 0n;
  let sumE = 0n;
  for (let j = 0; j < sessions; j++) {
    sumE += realised.es[j];
    sumS = mod(
      sumS + honestNonces[j].k1 + realised.bs[j] * honestNonces[j].k2 + realised.es[j] * qH,
      N,
    );
  }
  const sStar = mod(sumS + rhoStar + targeted.eStar * qA, N);
  const verified = verifyToy(bits, realised.Rstar, sStar, Q, forgedMsg);

  return {
    bits,
    sessions,
    probes,
    distinctTargets,
    targetDrifted: distinctTargets > 1,
    targetedEStar: targeted.eStar,
    actualEStar: realised.eStar,
    sumOfChallenges: sumE,
    aggregateKeyX: bytesToHex(xbytes(Q)),
    forgedR: bytesToHex(xbytes(realised.Rstar)),
    forgedS: bytesToHex(bigTo32(sStar)),
    verified,
    explanation:
      "Wagner's k-tree needs to know what sum it is searching for. Here the target is a function of the very nonce offsets being searched over: publishing them changes every b_j, which moves the honest contribution, which moves R*, which moves e*. Each row above is the same attack aiming at a different target, so there are no independent lists to build — the precondition fails before the search even starts.",
  };
}

/** Honest arithmetic on what the same algorithm costs without the truncation. */
export function fullWidthCost(k: number): string {
  const exponent = Math.round(256 / (1 + Math.log2(k)));
  return `At the real 256-bit challenge width, Wagner's k-tree with k = ${k} needs on the order of 2^${exponent} operations — far beyond anything reachable, which is why this is a break in theory and a demonstration only at reduced width.`;
}
