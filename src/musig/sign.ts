/**
 * BIP-327 round 2: partial signatures, partial-signature verification, and the
 * aggregation that collapses u partial signatures into ONE BIP-340 signature.
 *
 * The single equation each signer computes:
 *
 *     s_i = k_i1 + b·k_i2 + e·a_i·d_i      (mod n)
 *
 *   k_i1, k_i2   the signer's two secret nonces
 *   b            the nonce coefficient, = H(aggnonce ‖ Q ‖ m)
 *   e            the ordinary BIP-340 challenge, = H(R ‖ Q ‖ m)
 *   a_i          the signer's key-aggregation coefficient
 *   d_i          the signer's secret key
 *
 * Sum them and the structure telescopes exactly into a Schnorr signature:
 *
 *     Σ s_i = (Σ k_i1 + b·Σ k_i2) + e·(Σ a_i·d_i) = r + e·q
 *
 * where r is the discrete log of R and q is the discrete log of Q. So (R.x, Σs_i)
 * satisfies s·G = R + e·Q — the plain BIP-340 verification equation, under the
 * plain aggregate key. Nothing about the finished signature reveals that u
 * signers made it. That is the whole point of MuSig2.
 *
 * The sign-flip bookkeeping (`g`, and `k_i` negated when R has odd y) exists only
 * because BIP-340 serializes R and Q x-only: the group must agree on which of the
 * two y-parities each point had.
 *
 * NOT production crypto — a teaching demo.
 */
import {
  G,
  N,
  type Pt,
  add,
  bigTo32,
  bigToLen,
  bytesEqual,
  bytesToBig,
  bytesToHex,
  cbytes,
  concatBytes,
  cpoint,
  cpointExt,
  hasEvenY,
  mod,
  mul,
  negate,
  taggedHash,
  xbytes,
  xorBytes,
} from './field.js';
import {
  InvalidContributionError,
  type KeyAggContext,
  type PlainPk,
  getXonlyPk,
  keyAggAndTweak,
  sessionKeyAggCoeff,
} from './keyagg.js';
import { type AggNonce, type PubNonce, type SecNonce, nonceAgg } from './nonce.js';

/** Everything both signers and the aggregator must agree on for a session. */
export interface SessionContext {
  aggnonce: AggNonce;
  pubkeys: PlainPk[];
  /** Tweaks stay empty for this lab's exhibits; the spec KATs exercise them. */
  tweaks?: Uint8Array[];
  isXonly?: boolean[];
  msg: Uint8Array;
}

/** The six derived values every round-2 operation shares. */
export interface SessionValues {
  ctx: KeyAggContext;
  Q: Pt;
  gacc: bigint;
  tacc: bigint;
  b: bigint; // nonce coefficient
  R: Pt; // the signing nonce, R_1 + b·R_2
  e: bigint; // BIP-340 challenge
  R1: Pt;
  R2: Pt;
  /** True when R_1 + b·R_2 was infinity and the spec's G fallback kicked in. */
  usedInfinityFallback: boolean;
}

/**
 * Derive (Q, b, R, e) from a session context.
 *
 * Note the ordering: b is a hash of the *aggregate nonce bytes*, so it is fixed
 * before R exists, and R = R_1 + b·R_2 cannot be steered by a signer choosing
 * their nonce last. If R lands on infinity the spec substitutes R = G — an
 * unforgeable-but-defined fallback, since no signer knows a log for it that helps.
 */
export function getSessionValues(session: SessionContext): SessionValues {
  const ctx = keyAggAndTweak(session.pubkeys, session.tweaks ?? [], session.isXonly ?? []);
  const b = mod(
    bytesToBig(taggedHash('MuSig/noncecoef', session.aggnonce, xbytes(ctx.Q), session.msg)),
    N,
  );
  let R1: Pt;
  let R2: Pt;
  try {
    R1 = cpointExt(session.aggnonce.subarray(0, 33));
    R2 = cpointExt(session.aggnonce.subarray(33, 66));
  } catch {
    throw new InvalidContributionError(null, 'aggnonce');
  }
  const Rraw = add(R1, mul(R2, b));
  const usedInfinityFallback = Rraw.is0();
  const R = usedInfinityFallback ? G : Rraw;
  const e = mod(
    bytesToBig(taggedHash('BIP0340/challenge', xbytes(R), xbytes(ctx.Q), session.msg)),
    N,
  );
  return { ctx, Q: ctx.Q, gacc: ctx.gacc, tacc: ctx.tacc, b, R, e, R1, R2, usedInfinityFallback };
}

/** Per-signer detail behind one partial signature, for display. */
export interface PartialSignTrace {
  signerPubkey: string;
  k1: bigint;
  k2: bigint;
  /** k values after the R-parity flip — what actually enters the equation. */
  k1Effective: bigint;
  k2Effective: bigint;
  a: bigint;
  g: bigint;
  d: bigint; // effective secret after the Q-parity flip
  s: bigint;
  psigHex: string;
  rHasEvenY: boolean;
}

export interface PartialSignResult {
  psig: Uint8Array; // 32 bytes
  trace: PartialSignTrace;
}

/**
 * BIP-327 Sign. `secnonce` is CONSUMED: its 64 secret bytes are zeroed before
 * returning, so a second call with the same object fails loudly instead of
 * silently reusing a nonce. That fail-closed behaviour is the single most
 * important safety property in the whole file — nonce reuse across two different
 * messages leaks the secret key by simple algebra.
 */
export function sign(secnonce: SecNonce, sk: Uint8Array, session: SessionContext): PartialSignResult {
  const { Q, gacc, b, R, e } = getSessionValues(session);

  const k1Raw = bytesToBig(secnonce.subarray(0, 32));
  const k2Raw = bytesToBig(secnonce.subarray(32, 64));
  const pkFromNonce = secnonce.slice(64, 97);
  // Zero the secret halves before any early return can skip it.
  secnonce.fill(0, 0, 64);

  if (!(k1Raw > 0n && k1Raw < N)) throw new Error('first secnonce value is out of range');
  if (!(k2Raw > 0n && k2Raw < N)) throw new Error('second secnonce value is out of range');

  const rEven = hasEvenY(R);
  const k1 = rEven ? k1Raw : N - k1Raw;
  const k2 = rEven ? k2Raw : N - k2Raw;

  const dRaw = bytesToBig(sk);
  if (!(dRaw > 0n && dRaw < N)) throw new Error('secret key value is out of range');
  const Ppt = mul(G, dRaw);
  const pk = cbytes(Ppt);
  if (!bytesEqual(pk, pkFromNonce)) {
    throw new Error('public key does not match the nonce_gen argument');
  }

  const a = sessionKeyAggCoeff(session.pubkeys, Ppt);
  const g = hasEvenY(Q) ? 1n : N - 1n;
  const d = mod(g * gacc * dRaw, N);
  const s = mod(k1 + b * k2 + e * a * d, N);
  const psig = bigTo32(s);

  // Self-check, as the spec mandates: a signer must never emit a partial signature
  // that would not verify, or a faulty signer becomes indistinguishable from an
  // attacker and the session cannot be attributed.
  const pubnonce = concatBytes(cbytes(mul(G, k1Raw)), cbytes(mul(G, k2Raw)));
  if (!partialSigVerifyInternal(psig, pubnonce, pk, session)) {
    throw new Error('internal error: produced partial signature does not verify');
  }

  return {
    psig,
    trace: {
      signerPubkey: bytesToHex(pk),
      k1: k1Raw,
      k2: k2Raw,
      k1Effective: k1,
      k2Effective: k2,
      a,
      g,
      d,
      s,
      psigHex: bytesToHex(psig),
      rHasEvenY: rEven,
    },
  };
}

/**
 * Verify one partial signature against one signer's pubnonce and pubkey.
 * Checks  s_i·G = (R_i1 + b·R_i2)^{±} + e·a_i·g'·P_i  — the same equation the
 * signer solved, evaluated in the group instead of the scalar field.
 *
 * This is what makes MuSig2 attributable: if the final signature is bad, the
 * aggregator can name exactly which signer sent garbage.
 */
export function partialSigVerifyInternal(
  psig: Uint8Array,
  pubnonce: PubNonce,
  pk: PlainPk,
  session: SessionContext,
): boolean {
  const { Q, gacc, b, R, e } = getSessionValues(session);
  const s = bytesToBig(psig);
  if (psig.length !== 32 || s >= N) return false;
  const Rs1 = cpoint(pubnonce.subarray(0, 33));
  const Rs2 = cpoint(pubnonce.subarray(33, 66));
  const RsRaw = add(Rs1, mul(Rs2, b));
  const Rs = hasEvenY(R) ? RsRaw : negate(RsRaw);
  const Ppt = cpoint(pk);
  const a = sessionKeyAggCoeff(session.pubkeys, Ppt);
  const g = hasEvenY(Q) ? 1n : N - 1n;
  const gPrime = mod(g * gacc, N);
  return mul(G, s).equals(add(Rs, mul(Ppt, mod(e * a * gPrime, N))));
}

/** The public wrapper: aggregate the nonces, then verify signer `i`'s partial. */
export function partialSigVerify(
  psig: Uint8Array,
  pubnonces: PubNonce[],
  pubkeys: PlainPk[],
  msg: Uint8Array,
  i: number,
  tweaks: Uint8Array[] = [],
  isXonly: boolean[] = [],
): boolean {
  if (pubnonces.length !== pubkeys.length) {
    throw new Error('the `pubnonces` and `pubkeys` arrays must have the same length');
  }
  const session: SessionContext = { aggnonce: nonceAgg(pubnonces), pubkeys, tweaks, isXonly, msg };
  return partialSigVerifyInternal(psig, pubnonces[i], pubkeys[i], session);
}

export interface PartialSigAggTrace {
  terms: bigint[]; // each s_i
  sum: bigint; // Σ s_i mod n
  tweakCorrection: bigint; // e·g·tacc — zero for an untweaked group
  s: bigint; // the final scalar in the signature
  rx: string;
  signatureHex: string;
}

/**
 * BIP-327 PartialSigAgg: add up the scalars. That is the entire operation — no
 * pairing, no interaction, no per-signer data left in the output. `xbytes(R)` and
 * the 32-byte sum are the 64-byte BIP-340 signature.
 */
export function partialSigAgg(
  psigs: Uint8Array[],
  session: SessionContext,
): { sig: Uint8Array; trace: PartialSigAggTrace } {
  const { Q, tacc, R, e } = getSessionValues(session);
  const terms: bigint[] = [];
  let s = 0n;
  for (let i = 0; i < psigs.length; i++) {
    const si = bytesToBig(psigs[i]);
    if (psigs[i].length !== 32 || si >= N) throw new InvalidContributionError(i, 'psig');
    terms.push(si);
    s = mod(s + si, N);
  }
  const sum = s;
  const g = hasEvenY(Q) ? 1n : N - 1n;
  const tweakCorrection = mod(e * g * tacc, N);
  s = mod(s + tweakCorrection, N);
  const sig = concatBytes(xbytes(R), bigTo32(s));
  return {
    sig,
    trace: {
      terms,
      sum,
      tweakCorrection,
      s,
      rx: bytesToHex(xbytes(R)),
      signatureHex: bytesToHex(sig),
    },
  };
}

/**
 * BIP-327 DeterministicSign — the two-signer shortcut where the *last* signer
 * derives its nonce from the other signers' aggregate nonce instead of from fresh
 * randomness, removing the need for nonce state on that side.
 *
 * Implemented for spec-vector coverage; not surfaced in the UI, because it only
 * makes sense once you already understand the interactive two-round flow the
 * exhibits teach.
 *
 * [extension] point — a "stateless co-signer" exhibit would build on this.
 */
export function deterministicSign(
  sk: Uint8Array,
  aggothernonce: AggNonce,
  pubkeys: PlainPk[],
  msg: Uint8Array,
  rand: Uint8Array | null = null,
  tweaks: Uint8Array[] = [],
  isXonly: boolean[] = [],
): { pubnonce: PubNonce; psig: Uint8Array } {
  const skPrime = rand !== null ? xorBytes(sk, taggedHash('MuSig/aux', rand)) : sk;
  const aggpk = getXonlyPk(keyAggAndTweak(pubkeys, tweaks, isXonly));

  const detNonceHash = (i: number): bigint =>
    bytesToBig(
      taggedHash(
        'MuSig/deterministic/nonce',
        skPrime,
        aggothernonce,
        aggpk,
        bigToLen(BigInt(msg.length), 8),
        msg,
        new Uint8Array([i]),
      ),
    );
  const k1 = mod(detNonceHash(0), N);
  const k2 = mod(detNonceHash(1), N);
  if (k1 === 0n || k2 === 0n) throw new Error('derived nonce is zero (negligible probability)');

  const pubnonce = concatBytes(cbytes(mul(G, k1)), cbytes(mul(G, k2)));
  const dRaw = bytesToBig(sk);
  if (!(dRaw > 0n && dRaw < N)) throw new Error('secret key value is out of range');
  const secnonce = concatBytes(bigTo32(k1), bigTo32(k2), cbytes(mul(G, dRaw)));

  let aggnonce: AggNonce;
  try {
    aggnonce = nonceAgg([pubnonce, aggothernonce]);
  } catch {
    throw new InvalidContributionError(null, 'aggothernonce');
  }
  const { psig } = sign(secnonce, sk, { aggnonce, pubkeys, tweaks, isXonly, msg });
  return { pubnonce, psig };
}
