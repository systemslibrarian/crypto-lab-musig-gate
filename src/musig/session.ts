/**
 * One complete MuSig2 signing session, orchestrated and fully traced.
 *
 * This is the spine of the main exhibit: it runs the real two-round protocol from
 * fresh keys to a finished 64-byte signature and records every intermediate value,
 * so the UI can step through the aggregation instead of asserting it happened.
 *
 * The message is hashed to 32 bytes before signing. That is not a simplification —
 * it is what real deployments do (Bitcoin signs a 32-byte sighash), and it keeps
 * the final signature verifiable by a stock, unmodified BIP-340 verifier.
 *
 * Secrets live in memory for the life of the page and are never persisted.
 * NOT production crypto — a teaching demo.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import {
  bigTo32,
  bytesToHex,
  hexToBytes,
  individualPubkey,
  keySort,
  randomBytes,
  randomScalar,
  utf8,
  xbytes,
} from './field.js';
import { type VerifyResult, nobleVerify, verify } from './bip340.js';
import { type KeyAggTrace, type PlainPk, keyAggWithTrace } from './keyagg.js';
import { type NonceAggTrace, type PubNonce, nonceAgg, nonceAggWithTrace, nonceGen } from './nonce.js';
import {
  type PartialSigSides,
  type PartialSignTrace,
  type SessionContext,
  getSessionValues,
  partialSigAgg,
  partialSigSides,
  partialSigVerify,
  sign,
} from './sign.js';

export interface Signer {
  label: string; // "Signer 1"
  secretKey: Uint8Array; // 32 bytes, in memory only
  pubkey: PlainPk; // 33-byte plain key
}

export interface PartialRecord {
  label: string;
  psigHex: string;
  trace: PartialSignTrace;
  /** Independently verified by the aggregator before aggregation. */
  verified: boolean;
  /** The two sides of this signer's group equation, so equality can be shown. */
  sides: PartialSigSides;
}

export interface SessionResult {
  message: string;
  messageDigest: string; // the 32 bytes actually signed
  /**
   * Per-signer keys. `secretKey` is exposed deliberately: the whole point of the
   * round-2 exhibit is that a learner can check s_i = k_i1 + b·k_i2 + e·a_i·d_i by
   * hand, which is impossible without d_i. These are throwaway per-session keys
   * generated in the tab, never persisted and never sent anywhere.
   */
  signers: { label: string; pubkey: string; secretKey: string }[];
  keyAgg: KeyAggTrace;
  aggregateKeyX: string;
  round1: {
    pubnonces: { label: string; first: string; second: string }[];
    agg: NonceAggTrace;
  };
  sessionValues: {
    b: string; // nonce coefficient, hex
    rx: string; // x-only R
    e: string; // BIP-340 challenge, hex
    usedInfinityFallback: boolean;
  };
  round2: PartialRecord[];
  /** Σ s_i and the final scalar, so the sum can be checked by eye. */
  aggregation: {
    terms: string[];
    sum: string;
    s: string;
    signatureHex: string;
  };
  /** The plain single-signer verifier's verdict — the "aha". */
  verdict: VerifyResult;
  /** True when all u partial signatures verified individually. */
  allPartialsVerified: boolean;
}

/** Fresh signers with in-memory secret keys. */
export function makeSigners(count: number): Signer[] {
  if (count < 2 || count > 5) throw new Error('this exhibit runs 2 to 5 signers');
  return Array.from({ length: count }, (_, i) => {
    const secretKey = bigTo32(randomScalar());
    return { label: `Signer ${i + 1}`, secretKey, pubkey: individualPubkey(secretKey) };
  });
}

/** The 32 bytes a MuSig2 group actually signs, given human-typed text. */
export function messageDigest(text: string): Uint8Array {
  return sha256(utf8(text));
}

/**
 * Run the full protocol.
 *
 * `sortKeys` applies BIP-327 KeySort. KeyAgg is order-dependent, so a group must
 * either fix an order or sort; sorting is what lets signers derive the same
 * aggregate key from an unordered set. Flipping it visibly changes Q, which is a
 * lesson in itself.
 *
 * `tamperIndex` corrupts exactly one signer's partial signature after the fact, to
 * demonstrate that MuSig2 aggregation is *attributable*: the aggregator's
 * per-partial check names the culprit instead of producing a mystery bad signature.
 */
export function runSession(
  signers: Signer[],
  text: string,
  opts: { sortKeys?: boolean; tamperIndex?: number | null } = {},
): SessionResult {
  const msg = messageDigest(text);
  const pubkeys = opts.sortKeys ? keySort(signers.map((s) => s.pubkey)) : signers.map((s) => s.pubkey);

  // Keep each signer paired with its position in the (possibly sorted) key list.
  const ordered = pubkeys.map((pk) => {
    const found = signers.find((s) => bytesToHex(s.pubkey) === bytesToHex(pk));
    if (!found) throw new Error('internal error: key list does not match the signer set');
    return found;
  });

  // --- Key aggregation -----------------------------------------------------
  const { ctx, trace: keyAggTrace } = keyAggWithTrace(pubkeys);
  const aggpk = xbytes(ctx.Q);

  // --- Round 1: two nonces each, then aggregate ----------------------------
  const nonces = ordered.map((s) => nonceGen(s.secretKey, s.pubkey, aggpk, msg));
  const pubnonces: PubNonce[] = nonces.map((n) => n.pubnonce);
  const { aggnonce, trace: nonceTrace } = nonceAggWithTrace(pubnonces);

  const session: SessionContext = { aggnonce, pubkeys, msg };
  const sv = getSessionValues(session);

  // --- Round 2: partial signatures ----------------------------------------
  const round2: PartialRecord[] = ordered.map((s, i) => {
    // `sign` consumes the secnonce, so hand it the array it may zero out.
    const { psig, trace } = sign(nonces[i].secnonce, s.secretKey, session);
    return {
      label: s.label,
      psigHex: bytesToHex(psig),
      trace,
      verified: false,
      sides: partialSigSides(psig, pubnonces[i], pubkeys[i], session),
    };
  });

  let psigs = round2.map((r) => hexToBytes(r.psigHex));
  if (opts.tamperIndex != null) {
    const i = opts.tamperIndex;
    if (i < 0 || i >= psigs.length) throw new Error('tamperIndex out of range');
    // Flip one bit — the smallest possible corruption.
    const bad = psigs[i].slice();
    bad[31] ^= 0x01;
    psigs = psigs.map((p, j) => (j === i ? bad : p));
    round2[i] = { ...round2[i], psigHex: bytesToHex(bad) };
  }

  // The aggregator verifies each partial BEFORE combining, which is what makes a
  // failure attributable to a signer rather than to "the session".
  for (let i = 0; i < round2.length; i++) {
    round2[i].verified = partialSigVerify(psigs[i], pubnonces, pubkeys, msg, i);
    // Recomputed against the possibly-tampered scalar, so a corrupted partial
    // shows its two sides actually differing rather than a bare "false".
    round2[i].sides = partialSigSides(psigs[i], pubnonces[i], pubkeys[i], session);
  }

  // --- Aggregate and verify with a plain BIP-340 verifier ------------------
  const { sig, trace: aggTrace } = partialSigAgg(psigs, session);
  const verdict = verify(sig, msg, aggpk);

  return {
    message: text,
    messageDigest: bytesToHex(msg),
    signers: ordered.map((s) => ({
      label: s.label,
      pubkey: bytesToHex(s.pubkey),
      secretKey: bytesToHex(s.secretKey),
    })),
    keyAgg: keyAggTrace,
    aggregateKeyX: bytesToHex(aggpk),
    round1: {
      pubnonces: ordered.map((s, i) => ({
        label: s.label,
        first: nonceTrace.first.perSigner[i],
        second: nonceTrace.second.perSigner[i],
      })),
      agg: nonceTrace,
    },
    sessionValues: {
      b: bytesToHex(bigTo32(sv.b)),
      rx: bytesToHex(xbytes(sv.R)),
      e: bytesToHex(bigTo32(sv.e)),
      usedInfinityFallback: sv.usedInfinityFallback,
    },
    round2,
    aggregation: {
      terms: aggTrace.terms.map((t) => bytesToHex(bigTo32(t))),
      sum: bytesToHex(bigTo32(aggTrace.sum)),
      s: bytesToHex(bigTo32(aggTrace.s)),
      signatureHex: aggTrace.signatureHex,
    },
    verdict,
    allPartialsVerified: round2.every((r) => r.verified),
  };
}

/**
 * The comparison that lands the "aha": the SAME 64 bytes handed to a verifier that
 * knows nothing about MuSig, alongside a genuine one-signer signature. Both are
 * 64 bytes; both verify; nothing in either reveals how many signers there were.
 */
export function indistinguishability(result: SessionResult): {
  signatureBytes: number;
  aggregateKeyBytes: number;
  signerCount: number;
  handRolledValid: boolean;
  nobleValid: boolean;
  agree: boolean;
} {
  const sig = hexToBytes(result.aggregation.signatureHex);
  const pk = hexToBytes(result.aggregateKeyX);
  const msg = hexToBytes(result.messageDigest);
  return {
    signatureBytes: sig.length,
    aggregateKeyBytes: pk.length,
    signerCount: result.signers.length,
    handRolledValid: result.verdict.valid,
    nobleValid: nobleVerify(sig, msg, pk),
    agree: result.verdict.valid === nobleVerify(sig, msg, pk),
  };
}

/**
 * The lab's headline claim, set up as something a learner can be TESTED on rather
 * than told.
 *
 * We produce a genuine single-signer BIP-340 signature over the same message using
 * `@noble/curves`' own `schnorr.sign` — a library with no notion of MuSig at all —
 * and place it beside the group's aggregate signature. Both are 64 bytes, both
 * verify under a 32-byte x-only key through the same verifier, and which slot holds
 * which is decided by a WebCrypto coin flip so the panel can ask before it reveals.
 *
 * If the two were distinguishable, this function is where it would show up.
 */
export interface LoneSignerComparison {
  /** slot[0] and slot[1]; `groupSlot` says which one the group made. */
  slots: {
    keyX: string;
    signatureHex: string;
    signatureBytes: number;
    keyBytes: number;
    /** Verified through the hand-rolled BIP-340 verifier. */
    valid: boolean;
    /** Verified again through @noble/curves' independent verifier. */
    nobleValid: boolean;
  }[];
  groupSlot: 0 | 1;
  messageDigest: string;
  signerCount: number;
  /** True when nothing observable separates the two — the claim being tested. */
  indistinguishable: boolean;
  /** The specific properties compared, so "indistinguishable" is not a bare claim. */
  comparedProperties: { property: string; group: string; lone: string; same: boolean }[];
}

export function loneSignerComparison(result: SessionResult): LoneSignerComparison {
  const msg = hexToBytes(result.messageDigest);

  // A real, ordinary, one-person signature — made by the audited library, not by us.
  const lone = schnorr.keygen();
  const loneSig = schnorr.sign(msg, lone.secretKey);

  const groupSig = hexToBytes(result.aggregation.signatureHex);
  const groupKey = hexToBytes(result.aggregateKeyX);

  const describe = (sig: Uint8Array, key: Uint8Array) => ({
    keyX: bytesToHex(key),
    signatureHex: bytesToHex(sig),
    signatureBytes: sig.length,
    keyBytes: key.length,
    valid: verify(sig, msg, key).valid,
    nobleValid: nobleVerify(sig, msg, key),
  });
  const group = describe(groupSig, groupKey);
  const loneSlot = describe(loneSig, lone.publicKey);

  // A fair coin, so the reveal is a genuine question and not a fixed layout.
  const groupSlot: 0 | 1 = (randomBytes(1)[0] & 1) === 0 ? 0 : 1;
  const slots = groupSlot === 0 ? [group, loneSlot] : [loneSlot, group];

  const comparedProperties = [
    {
      property: 'Signature length',
      group: `${group.signatureBytes} bytes`,
      lone: `${loneSlot.signatureBytes} bytes`,
      same: group.signatureBytes === loneSlot.signatureBytes,
    },
    {
      property: 'Public key length',
      group: `${group.keyBytes} bytes (x-only)`,
      lone: `${loneSlot.keyBytes} bytes (x-only)`,
      same: group.keyBytes === loneSlot.keyBytes,
    },
    {
      property: 'Verifies under a plain BIP-340 verifier',
      group: group.valid ? 'yes' : 'no',
      lone: loneSlot.valid ? 'yes' : 'no',
      same: group.valid === loneSlot.valid,
    },
    {
      property: 'Verifies under @noble/curves’ own verifier',
      group: group.nobleValid ? 'yes' : 'no',
      lone: loneSlot.nobleValid ? 'yes' : 'no',
      same: group.nobleValid === loneSlot.nobleValid,
    },
    {
      property: 'Number of signers recoverable from these bytes',
      group: 'no',
      lone: 'no',
      same: true,
    },
  ];

  return {
    slots,
    groupSlot,
    messageDigest: result.messageDigest,
    signerCount: result.signers.length,
    indistinguishable: comparedProperties.every((p) => p.same),
    comparedProperties,
  };
}

/**
 * The n-of-n boundary, stated as code rather than prose: drop one signer and the
 * session cannot complete. MuSig2 is n-of-n — every listed signer must contribute.
 * A t-of-n quorum is a different scheme entirely (see crypto-lab-frost-threshold).
 */
export function dropOneSigner(
  signers: Signer[],
  text: string,
): { attempted: number; required: number; error: string; signature: null } {
  const msg = messageDigest(text);
  const pubkeys = signers.map((s) => s.pubkey);
  const subset = signers.slice(0, signers.length - 1);

  // The remaining signers run round 1 among themselves and try to sign for the
  // FULL key list — which is what a t-of-n attempt against an n-of-n group is.
  const nonces = subset.map((s) => nonceGen(s.secretKey, s.pubkey, xbytes(keyAggWithTrace(pubkeys).ctx.Q), msg));
  const partialAgg = nonceAgg(nonces.map((n) => n.pubnonce));
  const session: SessionContext = { aggnonce: partialAgg, pubkeys, msg };
  const psigs = subset.map((s, i) => sign(nonces[i].secnonce, s.secretKey, session).psig);
  const { sig } = partialSigAgg(psigs, session);
  const verdict = verify(sig, msg, xbytes(keyAggWithTrace(pubkeys).ctx.Q));

  return {
    attempted: subset.length,
    required: signers.length,
    error: verdict.valid
      ? 'unexpected: an incomplete signer set produced a valid signature'
      : `rejected — ${verdict.reason}. The missing signer's e·a_i·d_i term is absent from Σs_i, so s·G lands ${signers.length - subset.length} key-share short of R + e·Q.`,
    signature: null,
  };
}
