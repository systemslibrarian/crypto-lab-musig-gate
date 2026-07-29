/**
 * BIP-327 round 1: nonce generation and nonce aggregation.
 *
 * This is where MuSig2 differs from every naive "just add the nonces" scheme, and
 * the difference is the whole reason MuSig2 needs only two rounds.
 *
 * Each signer commits TWO nonces, not one:
 *   secnonce = k_1 ‖ k_2 ‖ pk        pubnonce = cbytes(k_1·G) ‖ cbytes(k_2·G)
 *
 * Aggregation sums each half independently:
 *   R_1 = Σ R_i1        R_2 = Σ R_i2        aggnonce = R_1 ‖ R_2
 *
 * The signing nonce is then R = R_1 + b·R_2 where
 *   b = int(H_"MuSig/noncecoef"(aggnonce ‖ xbytes(Q) ‖ m)) mod n.
 *
 * b is a hash of the aggregate nonce itself. A signer who publishes their nonce
 * last can freely steer R_1 and R_2 — but the moment they do, b changes, so the
 * R they were aiming at moves. Hitting a chosen R becomes a hash fixed-point
 * problem instead of one subtraction. With a single nonce there is no b, R is a
 * plain sum, and the last signer has exact control — which is what Wagner's
 * algorithm (and the polynomial-time ROS attack) turn into a forgery. See
 * noncecontrol.ts, where you can do the subtraction yourself and watch it stop
 * working once the second nonce is switched on.
 *
 * Either aggregate half can legitimately be the point at infinity (two signers
 * can cancel), which is why aggnonce uses the 33-zero-byte extended encoding.
 *
 * NOT production crypto — a teaching demo. In particular, a real signer must
 * persist secnonce to storage that guarantees it is used at most once.
 */
import {
  G,
  INFINITY,
  N,
  type Pt,
  add,
  bigToLen,
  bigTo32,
  bytesToBig,
  bytesToHex,
  cbytes,
  cbytesExt,
  concatBytes,
  cpoint,
  cpointExt,
  mod,
  mul,
  randomBytes,
  taggedHash,
  xbytes,
  xorBytes,
} from './field.js';
import { InvalidContributionError } from './keyagg.js';

/** 97 bytes: k_1 (32) ‖ k_2 (32) ‖ the signer's own plain pubkey (33). */
export type SecNonce = Uint8Array;
/** 66 bytes: cbytes(R_1) ‖ cbytes(R_2). */
export type PubNonce = Uint8Array;
/** 66 bytes: cbytes_ext(ΣR_i1) ‖ cbytes_ext(ΣR_i2) — either half may be infinity. */
export type AggNonce = Uint8Array;

/**
 * The nonce-derivation hash. Everything that could distinguish this signing
 * attempt from another goes in: the randomness, the signer's own key, the
 * aggregate key, the message, and a caller-supplied `extraIn` (a session id, a
 * counter, whatever the application has). Each field is length-prefixed so no
 * two different inputs can concatenate to the same buffer.
 */
export function nonceHash(
  rand: Uint8Array,
  pk: Uint8Array,
  aggpk: Uint8Array,
  i: number,
  msgPrefixed: Uint8Array,
  extraIn: Uint8Array,
): bigint {
  return bytesToBig(
    taggedHash(
      'MuSig/nonce',
      rand,
      bigToLen(BigInt(pk.length), 1),
      pk,
      bigToLen(BigInt(aggpk.length), 1),
      aggpk,
      msgPrefixed,
      bigToLen(BigInt(extraIn.length), 4),
      extraIn,
      bigToLen(BigInt(i), 1),
    ),
  );
}

export interface NonceGenResult {
  secnonce: SecNonce;
  pubnonce: PubNonce;
  k1: bigint;
  k2: bigint;
}

/**
 * NonceGen with the randomness supplied by the caller — the form the spec's
 * deterministic KATs pin down, and the form `nonceGen` wraps.
 *
 * When `sk` is present the caller's randomness is *hardened*: rand is XORed with
 * a hash of the secret key, so a fully broken RNG degrades to a deterministic
 * (still unique-per-message) nonce rather than an immediately repeated one.
 */
export function nonceGenInternal(
  randInput: Uint8Array,
  sk: Uint8Array | null,
  pk: Uint8Array,
  aggpk: Uint8Array | null,
  msg: Uint8Array | null,
  extraIn: Uint8Array | null,
): NonceGenResult {
  const rand = sk !== null ? xorBytes(sk, taggedHash('MuSig/aux', randInput)) : randInput;
  const aggpkBytes = aggpk ?? new Uint8Array(0);
  // A present-but-empty message and an absent message must not hash alike, so the
  // message is tagged with a presence byte and an 8-byte length.
  const msgPrefixed =
    msg === null
      ? new Uint8Array([0])
      : concatBytes(new Uint8Array([1]), bigToLen(BigInt(msg.length), 8), msg);
  const extra = extraIn ?? new Uint8Array(0);

  const k1 = mod(nonceHash(rand, pk, aggpkBytes, 0, msgPrefixed, extra), N);
  const k2 = mod(nonceHash(rand, pk, aggpkBytes, 1, msgPrefixed, extra), N);
  if (k1 === 0n || k2 === 0n) throw new Error('derived nonce is zero (negligible probability)');

  const pubnonce = concatBytes(cbytes(mul(G, k1)), cbytes(mul(G, k2)));
  const secnonce = concatBytes(bigTo32(k1), bigTo32(k2), pk);
  return { secnonce, pubnonce, k1, k2 };
}

/** NonceGen with fresh WebCrypto randomness. */
export function nonceGen(
  sk: Uint8Array | null,
  pk: Uint8Array,
  aggpk: Uint8Array | null,
  msg: Uint8Array | null,
  extraIn: Uint8Array | null = null,
): NonceGenResult {
  if (sk !== null && sk.length !== 32) throw new Error('the optional sk must have length 32');
  if (aggpk !== null && aggpk.length !== 32) throw new Error('the optional aggpk must have length 32');
  return nonceGenInternal(randomBytes(32), sk, pk, aggpk, msg, extraIn);
}

/** One half of the nonce aggregation, for display. */
export interface NonceAggHalf {
  perSigner: string[]; // x-only hex of each R_ij
  sum: string; // x-only hex of ΣR_ij, or "∞"
  isInfinity: boolean;
}

export interface NonceAggTrace {
  first: NonceAggHalf;
  second: NonceAggHalf;
  aggnonceHex: string;
}

/**
 * BIP-327 NonceAgg: sum each half independently. Throws
 * `InvalidContributionError(i, 'pubnonce')` naming the offending signer.
 */
export function nonceAgg(pubnonces: PubNonce[]): AggNonce {
  if (pubnonces.length === 0) throw new Error('nonce list is empty');
  const halves: Uint8Array[] = [];
  for (const j of [0, 1]) {
    let Rj: Pt = INFINITY;
    for (let i = 0; i < pubnonces.length; i++) {
      let Rij: Pt;
      try {
        Rij = cpoint(pubnonces[i].subarray(j * 33, j * 33 + 33));
      } catch {
        throw new InvalidContributionError(i, 'pubnonce');
      }
      Rj = add(Rj, Rij);
    }
    halves.push(cbytesExt(Rj));
  }
  return concatBytes(halves[0], halves[1]);
}

/** NonceAgg plus the per-signer breakdown of both halves. */
export function nonceAggWithTrace(pubnonces: PubNonce[]): { aggnonce: AggNonce; trace: NonceAggTrace } {
  const aggnonce = nonceAgg(pubnonces);
  const half = (j: 0 | 1): NonceAggHalf => {
    const pts = pubnonces.map((pn) => cpoint(pn.subarray(j * 33, j * 33 + 33)));
    const sum = cpointExt(aggnonce.subarray(j * 33, j * 33 + 33));
    return {
      perSigner: pts.map((p) => bytesToHex(xbytes(p))),
      sum: sum.is0() ? '∞' : bytesToHex(xbytes(sum)),
      isInfinity: sum.is0(),
    };
  };
  return {
    aggnonce,
    trace: { first: half(0), second: half(1), aggnonceHex: bytesToHex(aggnonce) },
  };
}
