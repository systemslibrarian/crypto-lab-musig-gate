/**
 * The BROKEN predecessors — isolated here, on purpose, and never the default.
 *
 * Two independent shortcuts that look obviously correct and are obviously wrong:
 *
 *   1. NAIVE KEY AGGREGATION.  Q = ΣP_i, no coefficients. Linear in the keys, so
 *      a signer who chooses their key after seeing everyone else's can subtract
 *      the others away and own the aggregate outright (rogue.ts).
 *
 *   2. SINGLE-NONCE AGGREGATION.  R = ΣR_i, no b coefficient. Linear in the
 *      nonces, so a signer who publishes their nonce last has exact control over
 *      the aggregate nonce, and therefore over the challenge (noncecontrol.ts).
 *      That control is the capability Wagner's generalised-birthday algorithm and
 *      the polynomial-time ROS attack convert into a full forgery.
 *
 * Nothing in this file is reachable from the normal signing path. It exists so
 * the learner can run the broken scheme against the SAME real verifier and watch
 * it break — a warning banner would teach far less.
 */
import {
  G,
  INFINITY,
  N,
  type Pt,
  add,
  bigTo32,
  concatBytes,
  cpoint,
  hasEvenY,
  mod,
  mul,
  xbytes,
} from './field.js';
import { challenge } from './bip340.js';
import type { PlainPk } from './keyagg.js';

/**
 * Plain point summation — the one linear step both broken shortcuts share, and the
 * reason both are reversible by whoever contributes last. `noncecontrol.ts` uses it
 * for the single-nonce aggregate; `naiveKeyAgg` below uses it for the key aggregate.
 */
export function sumPoints(points: Pt[], what: string): Pt {
  let acc: Pt = INFINITY;
  for (const pt of points) acc = add(acc, pt);
  if (acc.is0()) throw new Error(`naive ${what} is the point at infinity`);
  return acc;
}

/** BROKEN: Q = ΣP_i with no key-aggregation coefficients. */
export function naiveKeyAgg(pubkeys: PlainPk[]): Pt {
  return sumPoints(pubkeys.map(cpoint), 'aggregate key');
}

/**
 * BROKEN: R = ΣR_i from ONE nonce per signer, with no b coefficient.
 *
 * The named counterpart to BIP-327's `nonceAgg`, and the whole difference between
 * them: this one is a single reversible sum, so the last signer to publish decides
 * the result. `noncecontrol.ts` attacks exactly this.
 */
export function naiveNonceAgg(pubnonces: Pt[]): Pt {
  return sumPoints(pubnonces, 'aggregate nonce');
}

export interface NaiveSigner {
  /** Secret scalar as the signer holds it. */
  d: bigint;
  /** Single secret nonce. */
  k: bigint;
}

export interface NaiveSessionResult {
  /** x-only aggregate key the group would publish. */
  aggregateKeyX: Uint8Array;
  /** The 64-byte signature, in exactly BIP-340's wire format. */
  signature: Uint8Array;
  R: Pt;
  Q: Pt;
  e: bigint;
  partials: bigint[];
  s: bigint;
}

/**
 * Run the BROKEN single-nonce, no-coefficient protocol to completion.
 *
 * Each signer computes s_i = k_i + e·d_i with the parity flips BIP-340's x-only
 * encoding forces, and the sum is a genuine BIP-340 signature under Q = ΣP_i.
 * This scheme *works* when everyone is honest — which is precisely why it shipped
 * in the wild before the attacks were understood.
 */
export function naiveSign(signers: NaiveSigner[], msg: Uint8Array): NaiveSessionResult {
  const Q = sumPoints(signers.map((s) => mul(G, s.d)), 'aggregate key');
  const R = sumPoints(signers.map((s) => mul(G, s.k)), 'aggregate nonce');
  const qx = xbytes(Q);
  const e = challenge(xbytes(R), qx, msg);

  // x-only serialization pins both R and Q to their even-y representatives, so
  // each signer flips its scalars to match. Same bookkeeping as real BIP-340.
  const gQ = hasEvenY(Q) ? 1n : N - 1n;
  const gR = hasEvenY(R) ? 1n : N - 1n;

  const partials = signers.map((s) => mod(mod(gR * s.k, N) + e * mod(gQ * s.d, N), N));
  const sScalar = partials.reduce((acc, si) => mod(acc + si, N), 0n);

  return {
    aggregateKeyX: qx,
    signature: concatBytes(xbytes(R), bigTo32(sScalar)),
    R,
    Q,
    e,
    partials,
    s: sScalar,
  };
}
