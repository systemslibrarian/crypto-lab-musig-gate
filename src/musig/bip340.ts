/**
 * A plain, ordinary, single-signer BIP-340 Schnorr verifier.
 *
 * There is nothing MuSig-aware in this file, and that is the entire point. The
 * signature that comes out of a MuSig2 session is fed to *this* code — a verifier
 * that has never heard of key aggregation, nonce coefficients, or partial
 * signatures — and it accepts. A verifier cannot tell 1 signer from 5.
 *
 * We hand-roll it as an explicit stage pipeline so every rejection names its
 * cause, and we independently cross-check every result against @noble/curves'
 * own `schnorr.verify`. Two implementations agreeing is a much stronger claim
 * than one implementation asserting.
 */
import { schnorr } from '@noble/curves/secp256k1.js';
import {
  G,
  INFINITY,
  N,
  P,
  type Pt,
  add,
  bigTo32,
  bytesToBig,
  bytesToHex,
  hasEvenY,
  liftX,
  mod,
  mul,
  negate,
  pointHex,
  taggedHash,
} from './field.js';

/** The BIP-340 challenge e = int(H_"BIP0340/challenge"(R.x ‖ P.x ‖ m)) mod n. */
export function challenge(rx: Uint8Array, px: Uint8Array, msg: Uint8Array): bigint {
  return mod(bytesToBig(taggedHash('BIP0340/challenge', rx, px, msg)), N);
}

export interface VerifyStage {
  label: string;
  status: 'pass' | 'fail' | 'skipped';
  detail: string;
}

export interface VerifyResult {
  valid: boolean;
  reason: string;
  e: bigint | null;
  /** "Compute both sides and compare": s·G versus R + e·P, as x-only hex. */
  lhs: string | null;
  rhs: string | null;
  stages: VerifyStage[];
  /** @noble/curves' independent verdict on the same inputs. */
  nobleValid: boolean;
  /** True when the two implementations disagree — must never happen. */
  disagreement: boolean;
}

/**
 * Hand-rolled BIP-340 verification: parse → range-check → lift → challenge →
 * compare s·G against R + e·P. Ordered stages so the UI can show exactly where a
 * bad signature dies.
 */
export function verify(sig: Uint8Array, msg: Uint8Array, pubkey: Uint8Array): VerifyResult {
  const stages: VerifyStage[] = [];
  const nobleValid = nobleVerify(sig, msg, pubkey);
  const fail = (label: string, detail: string): VerifyResult => {
    stages.push({ label, status: 'fail', detail });
    return {
      valid: false,
      reason: detail,
      e: null,
      lhs: null,
      rhs: null,
      stages,
      nobleValid,
      disagreement: nobleValid,
    };
  };
  const pass = (label: string, detail: string): void => {
    stages.push({ label, status: 'pass', detail });
  };

  if (sig.length !== 64) return fail('Parse & lengths', `signature must be 64 bytes (got ${sig.length})`);
  if (pubkey.length !== 32) {
    return fail('Parse & lengths', `public key must be 32 bytes (got ${pubkey.length})`);
  }
  pass('Parse & lengths', 'signature is 64 bytes (R.x ‖ s); aggregate key is 32 bytes x-only');

  const px = bytesToBig(pubkey);
  const r = bytesToBig(sig.subarray(0, 32));
  const s = bytesToBig(sig.subarray(32, 64));
  if (px >= P) return fail('Range checks', 'public key x ≥ field size p — not a coordinate');
  if (r >= P) return fail('Range checks', 'signature R.x ≥ field size p');
  if (s >= N) return fail('Range checks', 'signature s ≥ group order n');
  pass('Range checks', 'P.x < p, R.x < p, and s < n');

  const Ppt = liftX(pubkey);
  if (!Ppt) return fail('Lift point', 'public key is not a valid x-coordinate on the curve');
  pass('Lift point', 'lifted the aggregate key to its even-y representative');

  const e = challenge(sig.subarray(0, 32), pubkey, msg);
  pass('Challenge', `e = H(R.x ‖ P.x ‖ m) mod n = 0x${e.toString(16).padStart(64, '0')}`);

  // R = s·G − e·P, then check it has even y and the right x. (Equivalent to
  // comparing s·G against R + e·P, but it is the form BIP-340 specifies, and it
  // catches the odd-y case that the naive comparison would miss.)
  const lhsPt: Pt = mul(G, s);
  const recovered = add(lhsPt, negate(mul(Ppt, e)));
  const rhsPt = add(liftXOrInfinity(sig.subarray(0, 32)), mul(Ppt, e));

  if (recovered.is0()) {
    return fail('Group equation', 's·G − e·P is the point at infinity');
  }
  if (!hasEvenY(recovered)) {
    return fail('Group equation', 'recovered R has odd y — BIP-340 requires even y');
  }
  if (recovered.x !== r) {
    stages.push({ label: 'Group equation', status: 'fail', detail: 's·G ≠ R + e·P' });
    return {
      valid: false,
      reason: 's·G ≠ R + e·P — signature rejected',
      e,
      lhs: pointHex(lhsPt),
      rhs: pointHex(rhsPt),
      stages,
      nobleValid,
      disagreement: nobleValid,
    };
  }
  pass('Group equation', 's·G equals R + e·P, and the recovered R has even y');

  return {
    valid: true,
    reason: 's·G equals R + e·P — signature valid under the aggregate key',
    e,
    lhs: pointHex(lhsPt),
    rhs: pointHex(rhsPt),
    stages,
    nobleValid,
    disagreement: !nobleValid,
  };
}

/** @noble/curves' verifier, wrapped so malformed input is `false`, not a throw. */
export function nobleVerify(sig: Uint8Array, msg: Uint8Array, pubkey: Uint8Array): boolean {
  try {
    return schnorr.verify(sig, msg, pubkey);
  } catch {
    return false;
  }
}

function liftXOrInfinity(b: Uint8Array): Pt {
  return liftX(b) ?? INFINITY;
}

/** Convenience for the UI: fixed 32-byte hex of a scalar. */
export function scalarHex(x: bigint): string {
  return bytesToHex(bigTo32(x));
}
