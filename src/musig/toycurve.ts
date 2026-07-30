/**
 * The real discrete group, small enough to draw.
 *
 * secp256k1 is y² = x³ + 7 over a 256-bit prime. Its group has about 2^256 points,
 * so there is no honest way to picture it: the usual smooth curve you see in
 * textbooks is the equation over the REAL numbers, which is a different object from
 * the finite group the cryptography actually happens in. Drawing that smooth curve
 * and putting point addition on it teaches a picture that contradicts the maths.
 *
 * So this module does the other thing: it keeps the arithmetic exactly and changes
 * only the size of the field. Same equation, y² = x³ + 7, over F_127. The result is a
 * genuine elliptic curve group with 127 elements — 126 affine points plus the point
 * at infinity — which is prime, so every non-identity point is a generator. The whole
 * group fits in a 127 × 127 grid, and every addition drawn from it is a real
 * addition, computed here with the same formulas the 256-bit version uses.
 *
 * What transfers: the group law, the fact that a scalar multiple lands somewhere
 * unrelated-looking, and the shape of key aggregation as a weighted sum of points.
 * What does not: security of any kind. A 127-element group is broken by counting to
 * 127, which is exactly why the real thing uses a 256-bit prime.
 */

/** The field prime. Small on purpose. */
export const TOY_P = 127n;
/** The curve is y² = x³ + 7 — the secp256k1 equation, unchanged. */
export const TOY_B = 7n;
/** The group order, #E(F_127) = 127. Prime, so every point generates. */
export const TOY_N = 127n;

/** A point on the toy curve; `null` is the point at infinity. */
export type ToyPoint = { x: bigint; y: bigint } | null;

const mod127 = (a: bigint): bigint => {
  const r = a % TOY_P;
  return r >= 0n ? r : r + TOY_P;
};

/** Modular inverse by Fermat: a^(p-2) mod p. */
function inv(a: bigint): bigint {
  if (mod127(a) === 0n) throw new Error('no inverse for zero');
  let result = 1n;
  let base = mod127(a);
  let exp = TOY_P - 2n;
  while (exp > 0n) {
    if (exp & 1n) result = mod127(result * base);
    base = mod127(base * base);
    exp >>= 1n;
  }
  return result;
}

/** Is this point actually on the curve? */
export function isOnCurve(pt: ToyPoint): boolean {
  if (pt === null) return true;
  return mod127(pt.y * pt.y) === mod127(pt.x * pt.x * pt.x + TOY_B);
}

/** The standard chord-and-tangent group law, over F_127 rather than over ℝ. */
export function toyAdd(a: ToyPoint, b: ToyPoint): ToyPoint {
  if (a === null) return b;
  if (b === null) return a;
  if (a.x === b.x && mod127(a.y + b.y) === 0n) return null; // P + (−P) = ∞
  let lambda: bigint;
  if (a.x === b.x && a.y === b.y) {
    // Tangent: λ = 3x² / 2y   (the curve has no x term, so no a-coefficient here)
    lambda = mod127(3n * a.x * a.x * inv(2n * a.y));
  } else {
    lambda = mod127((b.y - a.y) * inv(b.x - a.x));
  }
  const x = mod127(lambda * lambda - a.x - b.x);
  const y = mod127(lambda * (a.x - x) - a.y);
  return { x, y };
}

export function toyNegate(pt: ToyPoint): ToyPoint {
  return pt === null ? null : { x: pt.x, y: mod127(-pt.y) };
}

/** Double-and-add scalar multiplication — the same algorithm, a smaller field. */
export function toyMul(pt: ToyPoint, k: bigint): ToyPoint {
  let scalar = k % TOY_N;
  if (scalar < 0n) scalar += TOY_N;
  let acc: ToyPoint = null;
  let addend = pt;
  while (scalar > 0n) {
    if (scalar & 1n) acc = toyAdd(acc, addend);
    addend = toyAdd(addend, addend);
    scalar >>= 1n;
  }
  return acc;
}

export function toyEquals(a: ToyPoint, b: ToyPoint): boolean {
  if (a === null || b === null) return a === b;
  return a.x === b.x && a.y === b.y;
}

/** Every affine point on the curve, in (x, y) order. */
export function allToyPoints(): { x: bigint; y: bigint }[] {
  const squares = new Map<string, bigint[]>();
  for (let y = 0n; y < TOY_P; y++) {
    const key = String(mod127(y * y));
    const slot = squares.get(key);
    if (slot) slot.push(y);
    else squares.set(key, [y]);
  }
  const out: { x: bigint; y: bigint }[] = [];
  for (let x = 0n; x < TOY_P; x++) {
    const rhs = String(mod127(x * x * x + TOY_B));
    for (const y of squares.get(rhs) ?? []) out.push({ x, y });
  }
  return out;
}

/** The generator this module uses: the lowest-x point, deterministic and arbitrary. */
export function toyGenerator(): { x: bigint; y: bigint } {
  const pts = allToyPoints();
  if (pts.length === 0) throw new Error('the toy curve has no points');
  return pts[0];
}

/** The order of a point — with prime #E this is 1 for ∞ and TOY_N otherwise. */
export function toyOrder(pt: ToyPoint): bigint {
  if (pt === null) return 1n;
  let k = 1n;
  let acc: ToyPoint = pt;
  while (acc !== null) {
    acc = toyAdd(acc, pt);
    k++;
    if (k > TOY_N + 1n) throw new Error('order exceeded the group order — not a curve point?');
  }
  return k;
}

// ------------------------------------------------- key aggregation, drawn

/**
 * A tiny 32-bit FNV-1a-style hash. Deliberately NOT cryptographic.
 *
 * The toy group has 127 elements, so a coefficient is a number mod 127 — there is
 * nothing for SHA-256 to do at that size, and pretending otherwise would be theatre.
 * What the visualisation is showing is the SHAPE of BIP-327 key aggregation (each key
 * weighted by a coefficient derived from the whole key list, then summed), not its
 * byte-level specification. The real thing is in `keyagg.ts`, tested against the
 * spec's own vectors.
 */
function toyHash(parts: string[]): bigint {
  let h = 0x811c9dc5;
  for (const part of parts) {
    for (let i = 0; i < part.length; i++) {
      h ^= part.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    h ^= 0x2c; // separator, so ["ab","c"] and ["a","bc"] differ
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return BigInt(h);
}

const label = (pt: ToyPoint): string => (pt === null ? 'inf' : `${pt.x},${pt.y}`);

export interface ToyAggRow {
  index: number;
  point: { x: bigint; y: bigint };
  coeff: bigint;
  /** a_i·P_i — the weighted contribution. */
  weighted: ToyPoint;
  /** The running total after adding this contribution. */
  runningTotal: ToyPoint;
}

export interface ToyAggregation {
  rows: ToyAggRow[];
  /** Q = Σ a_i·P_i — the BIP-327-shaped aggregate. */
  aggregate: ToyPoint;
  /** Q = Σ P_i — the naive, forgeable one, for comparison. */
  naiveAggregate: ToyPoint;
  /** The running totals of the naive sum, for drawing its path. */
  naivePath: ToyPoint[];
  /** All curve points, for the background scatter. */
  allPoints: { x: bigint; y: bigint }[];
}

/**
 * Run the key-aggregation shape on the toy curve, recording every intermediate
 * point so the accumulation can be drawn as a path rather than described.
 */
export function toyAggregate(points: { x: bigint; y: bigint }[]): ToyAggregation {
  const list = points.map(label).join('|');
  const rows: ToyAggRow[] = [];
  let running: ToyPoint = null;
  points.forEach((point, index) => {
    // Coefficient 0 would erase a key, so the range is [1, n-1] as in the real thing.
    const coeff = (toyHash([list, label(point)]) % (TOY_N - 1n)) + 1n;
    const weighted = toyMul(point, coeff);
    running = toyAdd(running, weighted);
    rows.push({ index, point, coeff, weighted, runningTotal: running });
  });

  let naive: ToyPoint = null;
  const naivePath: ToyPoint[] = [];
  for (const point of points) {
    naive = toyAdd(naive, point);
    naivePath.push(naive);
  }

  return {
    rows,
    aggregate: running,
    naiveAggregate: naive,
    naivePath,
    allPoints: allToyPoints(),
  };
}

/** Pick `count` distinct random points, for the exhibit's "new keys" button. */
export function randomToyPoints(count: number): { x: bigint; y: bigint }[] {
  const pts = allToyPoints();
  const chosen: { x: bigint; y: bigint }[] = [];
  const used = new Set<string>();
  const bytes = new Uint8Array(count * 4);
  crypto.getRandomValues(bytes);
  let cursor = 0;
  while (chosen.length < count && cursor < bytes.length) {
    const pt = pts[bytes[cursor++] % pts.length];
    const key = label(pt);
    if (used.has(key)) continue;
    used.add(key);
    chosen.push(pt);
  }
  // Deterministic top-up in the unlikely event of repeated collisions.
  for (let i = 0; chosen.length < count && i < pts.length; i++) {
    const key = label(pts[i]);
    if (used.has(key)) continue;
    used.add(key);
    chosen.push(pts[i]);
  }
  return chosen;
}
