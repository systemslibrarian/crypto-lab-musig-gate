/**
 * BIP-327 key aggregation — hand-rolled, every coefficient inspectable.
 *
 * The idea in one line: you cannot just add public keys.
 *
 *   naive:      Q = P_1 + P_2 + … + P_u          <-- forgeable (see rogue.ts)
 *   BIP-327:    Q = a_1·P_1 + a_2·P_2 + … + a_u·P_u
 *
 * where the coefficient a_i = int(H_"KeyAgg coefficient"(L ‖ P_i)) mod n and
 * L = H_"KeyAgg list"(P_1 ‖ … ‖ P_u) commits to the WHOLE key list. Because a_i
 * depends on a hash of every key including P_i itself, a signer who picks their
 * key last can no longer steer Q anywhere they like: doing so would require
 * solving a hash fixed point. That is the entire rogue-key defence.
 *
 * The one wrinkle: the "second key" (the first key in the list that differs from
 * the first key) gets coefficient 1 instead of a hash. That is a deliberate
 * optimisation for the extremely common 1-of-my-own-keys case and is provably
 * safe — at most one signer gets the shortcut, so at least u−1 coefficients are
 * still hash-bound, which is enough to pin Q down.
 *
 * NOT production crypto — a teaching demo.
 */
import {
  G,
  INFINITY,
  N,
  type Pt,
  add,
  bytesEqual,
  bytesToBig,
  bytesToHex,
  cbytes,
  concatBytes,
  cpoint,
  hasEvenY,
  mod,
  mul,
  taggedHash,
  xbytes,
} from './field.js';

/** A 33-byte plain public key. */
export type PlainPk = Uint8Array;

/**
 * The aggregate-key context. `Q` is the aggregate point; `gacc`/`tacc` accumulate
 * the sign flips and additive offsets introduced by tweaking, and stay at 1/0 for
 * an untweaked group.
 */
export interface KeyAggContext {
  Q: Pt;
  gacc: bigint;
  tacc: bigint;
}

/** An error attributable to a specific misbehaving party, per the spec. */
export class InvalidContributionError extends Error {
  constructor(
    readonly signer: number | null,
    readonly contrib: 'pubkey' | 'pubnonce' | 'aggnonce' | 'aggothernonce' | 'psig',
  ) {
    super(`invalid ${contrib} contribution${signer === null ? '' : ` from signer ${signer}`}`);
    this.name = 'InvalidContributionError';
  }
}

/** L = tagged-hash("KeyAgg list", P_1 ‖ … ‖ P_u) — the commitment to the key set. */
export function hashKeys(pubkeys: PlainPk[]): Uint8Array {
  return taggedHash('KeyAgg list', concatBytes(...pubkeys));
}

/**
 * The "second key": the first entry that differs from `pubkeys[0]`, or 33 zero
 * bytes when every key is identical. Whichever key this is gets coefficient 1.
 */
export function getSecondKey(pubkeys: PlainPk[]): PlainPk {
  for (let j = 1; j < pubkeys.length; j++) {
    if (!bytesEqual(pubkeys[j], pubkeys[0])) return pubkeys[j];
  }
  return new Uint8Array(33);
}

/** a_i, given a precomputed L and the second key. */
export function keyAggCoeffInternal(L: Uint8Array, pk: PlainPk, pk2: PlainPk): bigint {
  if (bytesEqual(pk, pk2)) return 1n; // the second-key shortcut
  return mod(bytesToBig(taggedHash('KeyAgg coefficient', L, pk)), N);
}

/** a_i for `pk` within the list `pubkeys`. */
export function keyAggCoeff(pubkeys: PlainPk[], pk: PlainPk): bigint {
  return keyAggCoeffInternal(hashKeys(pubkeys), pk, getSecondKey(pubkeys));
}

/** Per-signer detail behind an aggregation, for display. */
export interface KeyAggRow {
  index: number;
  pubkey: string; // 33-byte compressed hex
  coeff: bigint; // a_i
  isSecondKey: boolean; // got the coefficient-1 shortcut
  contribution: string; // x-only hex of a_i·P_i
}

/** Everything a learner might want to see about one KeyAgg run. */
export interface KeyAggTrace {
  L: string; // hex of the key-list hash
  secondKey: string; // hex of the second key (or 33 zero bytes)
  rows: KeyAggRow[];
  aggregateX: string; // x-only hex of Q — the on-chain key
  aggregateCompressed: string; // 33-byte hex of Q, so the even/odd y is visible
  qHasEvenY: boolean;
}

/**
 * BIP-327 KeyAgg. Throws `InvalidContributionError(i, 'pubkey')` for the exact
 * offending index on a malformed key — the spec insists a bad contribution be
 * attributable, not just "the session failed".
 */
export function keyAgg(pubkeys: PlainPk[]): KeyAggContext {
  if (pubkeys.length === 0) throw new Error('key list is empty');
  const pk2 = getSecondKey(pubkeys);
  const L = hashKeys(pubkeys);
  let Q: Pt = INFINITY;
  for (let i = 0; i < pubkeys.length; i++) {
    let Pi: Pt;
    try {
      Pi = cpoint(pubkeys[i]);
    } catch {
      throw new InvalidContributionError(i, 'pubkey');
    }
    Q = add(Q, mul(Pi, keyAggCoeffInternal(L, pubkeys[i], pk2)));
  }
  // Q is infinity only with negligible probability for honestly-chosen keys, but
  // an adversary CAN force it, so fail closed rather than assert.
  if (Q.is0()) throw new Error('aggregate key is the point at infinity');
  return { Q, gacc: 1n, tacc: 0n };
}

/** KeyAgg plus the full per-coefficient trace the UI renders. */
export function keyAggWithTrace(pubkeys: PlainPk[]): { ctx: KeyAggContext; trace: KeyAggTrace } {
  const ctx = keyAgg(pubkeys);
  const L = hashKeys(pubkeys);
  const pk2 = getSecondKey(pubkeys);
  const rows: KeyAggRow[] = pubkeys.map((pk, index) => {
    const coeff = keyAggCoeffInternal(L, pk, pk2);
    const contribution = mul(cpoint(pk), coeff);
    return {
      index,
      pubkey: bytesToHex(pk),
      coeff,
      isSecondKey: bytesEqual(pk, pk2),
      contribution: contribution.is0() ? '∞' : bytesToHex(xbytes(contribution)),
    };
  });
  return {
    ctx,
    trace: {
      L: bytesToHex(L),
      secondKey: bytesToHex(pk2),
      rows,
      aggregateX: bytesToHex(xbytes(ctx.Q)),
      aggregateCompressed: bytesToHex(cbytes(ctx.Q)),
      qHasEvenY: hasEvenY(ctx.Q),
    },
  };
}

/** The 32-byte x-only aggregate key — what a verifier and a chain would see. */
export function getXonlyPk(ctx: KeyAggContext): Uint8Array {
  return xbytes(ctx.Q);
}

/**
 * BIP-327 ApplyTweak. Implemented for full spec-vector coverage (the tweak and
 * sig-agg KATs exercise it) but deliberately not surfaced in the UI: tweaking is
 * how a MuSig2 aggregate key becomes a Taproot output key, and Taproot output
 * assembly is crypto-lab-bitcoin-script's job, not this lab's.
 *
 * `isXonly` selects BIP-341 x-only tweaking (negate Q first if it has odd y)
 * versus plain tweaking. `gacc`/`tacc` carry the accumulated negation and offset
 * so signing and aggregation can undo them.
 *
 * [extension] point — a Taproot exhibit would build on exactly this call.
 */
export function applyTweak(ctx: KeyAggContext, tweak: Uint8Array, isXonly: boolean): KeyAggContext {
  if (tweak.length !== 32) throw new Error('the tweak must be a 32-byte array');
  const g = isXonly && !hasEvenY(ctx.Q) ? N - 1n : 1n;
  const t = bytesToBig(tweak);
  if (t >= N) throw new Error('the tweak must be less than n');
  const Q = add(mul(ctx.Q, g), mul(G, t));
  if (Q.is0()) throw new Error('the result of tweaking cannot be infinity');
  return { Q, gacc: mod(g * ctx.gacc, N), tacc: mod(t + g * ctx.tacc, N) };
}

/** KeyAgg followed by the ordered tweak list (BIP-327 KeyAggAndTweak). */
export function keyAggAndTweak(
  pubkeys: PlainPk[],
  tweaks: Uint8Array[] = [],
  isXonly: boolean[] = [],
): KeyAggContext {
  if (tweaks.length !== isXonly.length) {
    throw new Error('the `tweaks` and `isXonly` arrays must have the same length');
  }
  let ctx = keyAgg(pubkeys);
  for (let i = 0; i < tweaks.length; i++) ctx = applyTweak(ctx, tweaks[i], isXonly[i]);
  return ctx;
}

/** The coefficient for a signer's point within a session's key list. */
export function sessionKeyAggCoeff(pubkeys: PlainPk[], Pi: Pt): bigint {
  const pk = cbytes(Pi);
  if (!pubkeys.some((k) => bytesEqual(k, pk))) {
    throw new Error("the signer's pubkey must be included in the list of pubkeys");
  }
  return keyAggCoeff(pubkeys, pk);
}
