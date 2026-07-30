/**
 * Draw the real discrete group.
 *
 * Every dot on this plot is an actual solution of y² = x³ + 7 over F_127, and every
 * arrow is an actual addition in that group. It is deliberately NOT the smooth curve
 * from textbooks: that picture is the equation over the real numbers, a different
 * object from the finite group cryptography happens in, and drawing point addition on
 * it would teach something false. The only thing reduced here is the size of the
 * field — see toycurve.ts.
 *
 * The plot is decorative-free: it is generated from the same numbers the table beside
 * it lists, and it carries a text alternative, because a picture that is the only
 * place some information exists is an accessibility failure.
 */
import { h } from './dom.js';
import {
  TOY_P,
  type ToyAggregation,
  type ToyPoint,
} from '../musig/toycurve.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
const SIZE = 460; // plot area, px
const PAD = 26; // room for the axis ticks

function svgEl<K extends keyof SVGElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | number> = {},
  ...children: (Node | string)[]
): SVGElementTagNameMap[K] {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  for (const c of children) node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  return node;
}

const P = Number(TOY_P);
const px = (x: bigint): number => PAD + (Number(x) / (P - 1)) * SIZE;
/** y grows upward on the plot, unlike screen coordinates. */
const py = (y: bigint): number => PAD + SIZE - (Number(y) / (P - 1)) * SIZE;

const name = (pt: ToyPoint): string => (pt === null ? 'the point at infinity' : `(${pt.x}, ${pt.y})`);

export interface CurvePlotOptions {
  /** Also draw the naive Σ P_i accumulation, for contrast. */
  showNaive: boolean;
}

/**
 * The aggregation, drawn: faint dots for the whole group, numbered markers for the
 * input keys, and a path stepping through the running totals to the aggregate.
 */
export function curvePlot(agg: ToyAggregation, opts: CurvePlotOptions): HTMLElement {
  const svg = svgEl('svg', {
    viewBox: `0 0 ${SIZE + PAD * 2} ${SIZE + PAD * 2}`,
    class: 'curve-plot',
    role: 'img',
    'aria-label': describe(agg, opts),
  });

  // --- the whole group, as a faint scatter -------------------------------------
  const scatter = svgEl('g', { class: 'cp-all' });
  for (const pt of agg.allPoints) {
    scatter.append(svgEl('circle', { cx: px(pt.x), cy: py(pt.y), r: 2.4 }));
  }
  svg.append(axes(), scatter);

  // --- the naive accumulation, for contrast ------------------------------------
  if (opts.showNaive) {
    const naive = svgEl('g', { class: 'cp-naive' });
    const pts = agg.naivePath.filter((p): p is { x: bigint; y: bigint } => p !== null);
    if (pts.length > 1) {
      naive.append(
        svgEl('polyline', {
          points: pts.map((p) => `${px(p.x)},${py(p.y)}`).join(' '),
          fill: 'none',
        }),
      );
    }
    if (agg.naiveAggregate) {
      naive.append(
        svgEl('circle', {
          cx: px(agg.naiveAggregate.x),
          cy: py(agg.naiveAggregate.y),
          r: 7,
          class: 'cp-naive-end',
        }),
      );
    }
    svg.append(naive);
  }

  // --- the weighted accumulation path ------------------------------------------
  const path = svgEl('g', { class: 'cp-path' });
  const totals = agg.rows.map((r) => r.runningTotal).filter((p): p is { x: bigint; y: bigint } => p !== null);
  if (totals.length > 1) {
    path.append(
      svgEl('polyline', {
        points: totals.map((p) => `${px(p.x)},${py(p.y)}`).join(' '),
        fill: 'none',
      }),
    );
  }
  svg.append(path);

  // --- the input keys, numbered -------------------------------------------------
  const keys = svgEl('g', { class: 'cp-keys' });
  agg.rows.forEach((row) => {
    keys.append(svgEl('circle', { cx: px(row.point.x), cy: py(row.point.y), r: 8 }));
    keys.append(
      svgEl(
        'text',
        { x: px(row.point.x), y: py(row.point.y) + 3.5, 'text-anchor': 'middle', class: 'cp-num' },
        String(row.index + 1),
      ),
    );
    // Where the coefficient sent it.
    if (row.weighted) {
      keys.append(
        svgEl('circle', {
          cx: px(row.weighted.x),
          cy: py(row.weighted.y),
          r: 5,
          class: 'cp-weighted',
        }),
      );
      keys.append(
        svgEl('line', {
          x1: px(row.point.x),
          y1: py(row.point.y),
          x2: px(row.weighted.x),
          y2: py(row.weighted.y),
          class: 'cp-kick',
        }),
      );
    }
  });
  svg.append(keys);

  // --- the aggregate ------------------------------------------------------------
  if (agg.aggregate) {
    svg.append(
      svgEl('circle', {
        cx: px(agg.aggregate.x),
        cy: py(agg.aggregate.y),
        r: 10,
        class: 'cp-agg',
      }),
      svgEl(
        'text',
        {
          x: px(agg.aggregate.x),
          y: py(agg.aggregate.y) + 4,
          'text-anchor': 'middle',
          class: 'cp-agg-label',
        },
        'Q',
      ),
    );
  }

  return h(
    'figure',
    { class: 'curve-figure' },
    svg,
    h(
      'figcaption',
      {},
      h(
        'span',
        { class: 'cp-legend' },
        legendSwatch('cp-swatch-key'),
        ' input key P_i  ',
        legendSwatch('cp-swatch-weighted'),
        ' a_i·P_i  ',
        legendSwatch('cp-swatch-path'),
        ' running total  ',
        legendSwatch('cp-swatch-agg'),
        ' aggregate Q  ',
        ...(opts.showNaive ? [legendSwatch('cp-swatch-naive'), ' naive Σ P_i'] : []),
      ),
      h(
        'span',
        { class: 'cp-caption-text' },
        'All 126 points of y² = x³ + 7 over F_127, plus the point at infinity — the same curve equation as secp256k1, over a 7-bit prime instead of a 256-bit one so the whole group fits on screen. Every dot is a real solution and every step is a real addition. A 127-element group offers no security whatsoever; only the picture is small.',
      ),
    ),
  );
}

function legendSwatch(cls: string): HTMLElement {
  return h('span', { class: `cp-swatch ${cls}`, 'aria-hidden': 'true' });
}

function axes(): SVGGElement {
  const g = svgEl('g', { class: 'cp-axes' });
  g.append(
    svgEl('line', { x1: PAD, y1: PAD + SIZE, x2: PAD + SIZE, y2: PAD + SIZE }),
    svgEl('line', { x1: PAD, y1: PAD, x2: PAD, y2: PAD + SIZE }),
  );
  for (const tick of [0n, 63n, 126n]) {
    g.append(
      svgEl(
        'text',
        { x: px(tick), y: PAD + SIZE + 16, 'text-anchor': 'middle', class: 'cp-tick' },
        String(tick),
      ),
      svgEl(
        'text',
        { x: PAD - 6, y: py(tick) + 3, 'text-anchor': 'end', class: 'cp-tick' },
        String(tick),
      ),
    );
  }
  // Axis labels sit INSIDE the plot area: at the outer edge they collide with the
  // 126 tick, which anchors to the same pixel.
  g.append(
    svgEl(
      'text',
      { x: PAD + SIZE - 6, y: PAD + SIZE - 8, 'text-anchor': 'end', class: 'cp-axis-label' },
      'x',
    ),
    svgEl('text', { x: PAD + 8, y: PAD + 14, 'text-anchor': 'start', class: 'cp-axis-label' }, 'y'),
  );
  return g;
}

/** The plot's text alternative — the same facts, in words. */
function describe(agg: ToyAggregation, opts: CurvePlotOptions): string {
  const parts = agg.rows.map(
    (r) => `key ${r.index + 1} at ${name(r.point)} weighted by ${r.coeff} lands on ${name(r.weighted)}`,
  );
  const naive = opts.showNaive ? ` The naive sum of the same keys lands on ${name(agg.naiveAggregate)}.` : '';
  return `Scatter plot of all 126 points of the curve y squared equals x cubed plus 7 over the field of 127 elements. ${parts.join('; ')}. The weighted contributions sum to the aggregate key Q at ${name(agg.aggregate)}.${naive} The same values are listed in the coefficient table below this figure.`;
}
