/**
 * secp256k1 group parameters plus the byte/point encodings BIP-327 fixes.
 *
 * Group arithmetic (point add/multiply, field sqrt, scalar inverse) comes from
 * @noble/curves — audited, and NOT the teaching subject. The teaching subject is
 * MuSig2 itself (key-aggregation coefficients, the two-nonce coefficient b, the
 * partial-signature equation), which is hand-rolled in keyagg.ts / nonce.ts /
 * sign.ts on top of these primitives so every intermediate value is inspectable.
 *
 * BIP-327 uses TWO public-key encodings and they are not interchangeable:
 *   - "plain" 33-byte compressed keys (0x02/0x03 ‖ x) for INDIVIDUAL signer keys
 *     and nonces. Full y-coordinate — a signer's key is not ±ambiguous.
 *   - 32-byte x-only keys (BIP-340) for the AGGREGATE key that finally goes on
 *     chain, and for R in the finished signature.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

/** Projective point class for secp256k1 (BASE, multiply, add, fromAffine, Fp, Fn). */
export const Point = secp256k1.Point;
export type Pt = InstanceType<typeof Point>;

const CURVE = Point.CURVE();

/** Field prime p — coordinates live in F_p.  (2^256 − 2^32 − 977) */
export const P: bigint = CURVE.p;
/** Group order n — scalars (secret keys, nonces, challenges) live in Z_n. */
export const N: bigint = CURVE.n;
/** Generator / base point G. */
export const G: Pt = Point.BASE;
/** The point at infinity — a real element of the group, and a real edge case here. */
export const INFINITY: Pt = Point.ZERO;

/** Least non-negative residue of a mod m (JS `%` keeps the sign of the dividend). */
export function mod(a: bigint, m: bigint = N): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

/** Modular inverse in Z_n (throws on 0). */
export function invN(a: bigint): bigint {
  return Point.Fn.inv(mod(a, N));
}

/**
 * Scalar multiply that tolerates the scalar 0 by returning infinity.
 * noble's `multiply` rejects 0; MuSig2 genuinely reaches it (a coefficient or an
 * aggregate nonce half can be zero), and the spec's behaviour there is defined.
 */
export function mul(pt: Pt, k: bigint): Pt {
  if (pt.is0()) return INFINITY;
  const s = mod(k, N);
  return s === 0n ? INFINITY : pt.multiply(s);
}

/** Point addition that tolerates infinity on either side. */
export function add(a: Pt, b: Pt): Pt {
  return a.add(b);
}

/** Negate a point: −(x, y) = (x, p − y). Infinity negates to itself. */
export function negate(pt: Pt): Pt {
  return pt.negate();
}

/** BIP-340 has_even_y. Undefined for infinity, which callers must exclude first. */
export function hasEvenY(pt: Pt): boolean {
  if (pt.is0()) throw new Error('has_even_y is undefined for the point at infinity');
  return mod(pt.y, 2n) === 0n;
}

/** `len` cryptographically-random bytes (browser or Node WebCrypto). */
export function randomBytes(len = 32): Uint8Array {
  const out = new Uint8Array(len);
  crypto.getRandomValues(out);
  return out;
}

/** A uniform scalar in [1, n-1] — rejection-sampled, never `mod n` of 32 bytes. */
export function randomScalar(): bigint {
  for (;;) {
    const x = bytesToBig(randomBytes(32));
    if (x >= 1n && x < N) return x;
  }
}

// ---------------------------------------------------------------- bytes <-> ints

export function bytesToBig(b: Uint8Array): bigint {
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return x;
}

/** Fixed 32-byte big-endian encoding (throws if the value doesn't fit). */
export function bigTo32(x: bigint): Uint8Array {
  if (x < 0n || x >= 1n << 256n) throw new Error('value out of 32-byte range');
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/** Big-endian encoding of `x` in exactly `len` bytes (the spec's bytes(len, x)). */
export function bigToLen(x: bigint, len: number): Uint8Array {
  if (x < 0n) throw new Error('negative value');
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error(`value does not fit in ${len} bytes`);
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.replace(/\s+/g, '');
  // Validate the ENTIRE string up front. parseInt() stops at the first invalid
  // character and silently accepts a valid prefix ("0g" -> 0), so a per-pair
  // parse would let malformed input through. Fail closed instead.
  if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex character');
  if (h.length % 2 !== 0) throw new Error('odd-length hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (const byte of b) s += byte.toString(16).padStart(2, '0');
  return s;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(arrays.reduce((k, a) => k + a.length, 0));
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** UTF-8 encode a human-typed message. */
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

// ---------------------------------------------------------------- tagged hashes

/**
 * BIP-340 tagged hash:  SHA256( SHA256(tag) ‖ SHA256(tag) ‖ data ).
 * The doubled tag-hash prefix domain-separates every use of SHA-256 in the
 * scheme, so a digest produced for "KeyAgg coefficient" can never be replayed as
 * a "MuSig/noncecoef" or a BIP-340 challenge. MuSig2 leans on five distinct
 * tags: KeyAgg list, KeyAgg coefficient, MuSig/aux, MuSig/nonce,
 * MuSig/noncecoef — plus BIP0340/challenge, shared with plain Schnorr, which is
 * exactly why the finished signature is an ordinary BIP-340 signature.
 */
export function taggedHash(tag: string, ...data: Uint8Array[]): Uint8Array {
  const tagHash = sha256(utf8(tag));
  return sha256(concatBytes(tagHash, tagHash, ...data));
}

// ---------------------------------------------------------------- point codecs

/**
 * BIP-340 lift_x: the unique curve point with the given x and EVEN y.
 * Returns null if x ≥ p or x is not an x-coordinate on the curve — the
 * fail-closed cases the spec's malformed-key vectors exercise.
 */
export function liftX(b: Uint8Array): Pt | null {
  const x = bytesToBig(b);
  if (x >= P) return null;
  const Fp = Point.Fp;
  const ySq = mod(x * x * x + 7n, P); // secp256k1: y² = x³ + 7
  let y: bigint;
  try {
    y = Fp.sqrt(ySq); // p ≡ 3 (mod 4) ⇒ sqrt is c^((p+1)/4); throws on a non-residue
  } catch {
    return null;
  }
  if (mod(y * y, P) !== ySq) return null; // x is not on the curve
  try {
    const pt = Point.fromAffine({ x, y: mod(y, 2n) === 0n ? y : P - y });
    pt.assertValidity();
    return pt;
  } catch {
    return null;
  }
}

/** 32-byte x-only serialization (BIP-340 aggregate keys and R). */
export function xbytes(pt: Pt): Uint8Array {
  if (pt.is0()) throw new Error('cannot x-only-serialize the point at infinity');
  return bigTo32(pt.x);
}

/** 33-byte compressed serialization: 0x02 (even y) / 0x03 (odd y) ‖ x. */
export function cbytes(pt: Pt): Uint8Array {
  if (pt.is0()) throw new Error('cannot compress the point at infinity');
  return concatBytes(new Uint8Array([hasEvenY(pt) ? 2 : 3]), xbytes(pt));
}

/** cbytes, but infinity serializes as 33 zero bytes (used for aggregate nonces). */
export function cbytesExt(pt: Pt): Uint8Array {
  return pt.is0() ? new Uint8Array(33) : cbytes(pt);
}

/** Parse a 33-byte compressed point. Throws on any malformed encoding. */
export function cpoint(b: Uint8Array): Pt {
  if (b.length !== 33) throw new Error('not a valid compressed point: wrong length');
  const lifted = liftX(b.subarray(1, 33));
  if (!lifted) throw new Error('not a valid compressed point: x is not on the curve');
  if (b[0] === 2) return lifted;
  if (b[0] === 3) return negate(lifted);
  throw new Error('not a valid compressed point: prefix byte is not 0x02 or 0x03');
}

/** cpoint, but 33 zero bytes decode to infinity (used for aggregate nonces). */
export function cpointExt(b: Uint8Array): Pt {
  if (b.length !== 33) throw new Error('not a valid compressed point: wrong length');
  if (b.every((byte) => byte === 0)) return INFINITY;
  return cpoint(b);
}

/** Display helper: x-only hex, or the infinity symbol. */
export function pointHex(pt: Pt): string {
  return pt.is0() ? '∞' : bytesToHex(xbytes(pt));
}

/** The 33-byte plain public key for a secret scalar (BIP-327 IndividualPubkey). */
export function individualPubkey(seckey: Uint8Array): Uint8Array {
  const d0 = bytesToBig(seckey);
  if (d0 < 1n || d0 > N - 1n) throw new Error('secret key must be in [1, n-1]');
  return cbytes(mul(G, d0));
}

/**
 * BIP-327 KeySort: lexicographic order on the 33-byte encodings. Optional in the
 * spec — KeyAgg itself is order-DEPENDENT, so a group either fixes an order or
 * sorts. Sorting is what lets every signer derive the same aggregate key from an
 * unordered set.
 */
export function keySort(pubkeys: Uint8Array[]): Uint8Array[] {
  return [...pubkeys].sort((a, b) => (bytesToHex(a) < bytesToHex(b) ? -1 : 1));
}
