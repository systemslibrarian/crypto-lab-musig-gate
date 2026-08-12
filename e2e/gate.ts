import AxeBuilder from '@axe-core/playwright';
import type { Result } from 'axe-core';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Four landmark rules axe classifies as "best-practice" rather than tagging
 * `wcag*`, so `withTags(TAGS)` alone does not run them. This page has the shape
 * they catch: a shared `<header role="banner">` above a `<div id="app">` that
 * holds a hero `<aside>`, a `<main>`, and one named `<aside class="bridge">` per
 * exhibit inside that `<main>`.
 */
export const EXTRA_RULES = [
  'landmark-no-duplicate-banner',
  'landmark-unique',
  'landmark-one-main',
  'landmark-complementary-is-top-level',
];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * WHAT THE GATE THIS REPLACES ACTUALLY DID. It was one `driveDemos()` walk
 * followed by a single `scan()`, twice — once per theme, both at the default
 * 1280x720 — and the walk was built out of five things that each turned a
 * failure into a silent pass:
 *
 *  1. EVERY STEP WAS SWALLOWED. `click()` ended in `.catch(() => {})` and
 *     `clickByText()` opened with `if (!(await btn.isVisible())) return`. A
 *     control that had been renamed, or that never rendered because its panel
 *     threw, produced no error and no scan of the state it was supposed to
 *     build — the run simply moved on. Roughly forty of the drive's steps were
 *     guarded that way, so the same green result was reachable with most of the
 *     lab missing.
 *
 *  2. IT ASSEMBLED A DOCUMENT NO VISITOR CAN REACH. Its last real act was
 *     `document.querySelectorAll('details').forEach(d => d.open = true)` and
 *     `document.querySelectorAll('[hidden]').forEach(el => el.removeAttribute('hidden'))`.
 *     That opened all 56 BIP-327 vector cases at once and, worse, unhid all
 *     five `<section class="panel">` tabpanels simultaneously — a page that
 *     cannot exist, because `selectTab()` hides four of them on every switch.
 *     Whatever axe then measured was a layout no reader will ever load. This
 *     gate never writes `open`, never touches `hidden`, and reaches every
 *     disclosure by clicking its own `<summary>`.
 *
 *  3. IT SCANNED ONCE, AT THE END. Every state the drive built — the corrupted
 *     partial, the malformed-key rejection, the rogue-key alarm, both Wagner
 *     forgeries, the ROS forgery, the wrong-answer `.match-bad` styling — was
 *     overwritten by the next step before anything measured it. Only the final
 *     frame was ever asserted on. This gate scans after every single step.
 *
 *  4. IT INJECTED `animation:none!important; transition:none!important` THROUGH
 *     `addStyleTag`, and did it AFTER the drive rather than before the load. It
 *     therefore never exercised `style.css`'s own
 *     `@media (prefers-reduced-motion: reduce)` block, which is the thing a
 *     reader with the preference actually gets. That block cancels `.reveal`
 *     (a `0 → 1` opacity keyframe) and `.tour-flash`; cancelling an opacity
 *     animation strands the element at its start value in stylesheets that
 *     declare no end state, and an injected `animation:none` cannot tell the
 *     safe case from the broken one. `boot()` asks for the preference, ASSERTS
 *     it took effect, and `expectNotBlank` measures the outcome in every state.
 *
 *  5. ITS 1.4.11 CHECK WAS SELF-CONFIRMING. `minimumControlBoundaryRatio()`
 *     queried exactly `.mono-input, .msg-input` — the set the palette's
 *     `--control-border` token was written for and correctly applied to — and
 *     compared each control's border to its own FILL, never to the panel
 *     outside it. Every button on the page draws its edge from `--border`, a
 *     surface divider, and was never measured. It also ran BEFORE `driveDemos`,
 *     so it only ever saw the controls present at first paint. See
 *     `nontext.ts`, which measures every control against what surrounds it, in
 *     every driven state.
 *
 * Two other holes: it asserted `violations` only, so the entire `incomplete`
 * bucket (where a prohibited `aria-label` and any surface axe declines to
 * resolve both land) went unread; and it had no reflow oracle and no phone
 * viewport, so WCAG 1.4.10 was never tested at all.
 *
 * HAND-MEASURED, BECAUSE NOTHING AUTOMATED REACHES THEM. Two classes have no
 * oracle in this file or in `nontext.ts` — SVG shapes, which own no text node
 * and are not controls, and `background-image` chevrons drawn on a `<select>`.
 * Measured from the composited colours the page actually paints:
 *
 *  - The two drawn `<select>` chevrons, `--accent-text` triangles on the
 *    `--bg` fill of `.mono-input`: 6.18:1 dark (#d67a4a on #100e0c) and 6.69:1
 *    light (#8a4415 on #faf6f1). Both clear the 3:1 SC 1.4.11 asks.
 *  - The curve plot's numbered key markers, `.cp-num` (`--accent-ink`) over
 *    `.cp-keys circle` (`--accent`): 6.14:1, and the `Q` marker
 *    `.cp-agg-label` over `.cp-agg` (`--ok`): 8.39:1 dark. Both are text and
 *    both clear 4.5:1. (These two the contrast walk DOES reach, via
 *    `svgUnderlay`; they are listed because they are the reason it exists.)
 *  - The plot's own marks against the `--surface-2` panel they are drawn on.
 *    This is where the hand pass found real failures, since neither oracle
 *    reaches an SVG `<circle>` or a CSS legend swatch. Before: `--accent`
 *    2.64:1 in light for the key markers, the accumulation path, the weighted
 *    markers and three of the five legend swatches, and `.cp-kick` 2.36:1 with
 *    its 0.75 opacity applied. After `--accent-strong` and dropping that
 *    opacity: 3.22:1 light / 5.41:1 dark for all of them.
 *  - `.cp-all circle`, the 126-dot backdrop, is left at 2.90:1 dark and 2.25:1
 *    light on purpose, with the reasoning and both numbers recorded beside the
 *    rule in `style.css`.
 *  - `input[type=range]` and `input[type=checkbox]` are painted by the UA with
 *    an author `accent-color: var(--accent)`. `nontext.ts` skips native widgets
 *    with `appearance: auto`, so these were measured by hand: `--accent` against
 *    the `--surface` of the `.controls` panel every one of them sits in is
 *    6.10:1 dark and 3.11:1 light.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page has exactly the shape that can go wrong. `.reveal` is
 * `animation: reveal 0.22s ease` over a keyframe running `opacity: 0` to
 * `opacity: 1`, the reduced-motion block sets `.reveal { animation: none }`,
 * and the class is applied to nearly every result block the exhibits render.
 * It is SAFE — `opacity` is not declared on `.reveal` itself, so cancelling the
 * animation leaves the initial value of `1` rather than the keyframe's `0` —
 * but that is a property of one missing declaration, and the assertion is what
 * turns "safe" into a measurement. It runs in every driven state.
 *
 * `aria-hidden` subtrees are excluded: text removed from the accessibility tree
 * AND painted at zero opacity is not checked here. On this page that set is
 * enumerated in `contrast.ts`'s header and is entirely glyphs duplicating an
 * adjacent word.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. That is not hypothetical here: `ensureRendered()` catches a throwing
 * panel, logs `console.error`, and replaces the exhibit with an apology — which
 * is good behaviour for a reader and invisible to an assertion about the DOM.
 * Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * Asserting the OUTCOME rather than the mechanism matters here, because there
 * IS a mechanism: `index.html`'s `dedupeBanner()` demotes any other
 * `role="banner"` or unscoped `<header>` to `role="group"`. This lab's hero is
 * a `<div class="cl-hero">` rather than a `<header>`, so today nothing needs
 * demoting — and a change to either the hero's element or the shared script
 * would be caught by the count rather than by an assertion about whichever one
 * happened to be inspected.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the
 * toggle, which also pins down a real failure mode: `index.html`'s anti-flash
 * script reads `localStorage.getItem('theme')` and the bar's toggle writes
 * `localStorage.setItem('theme', …)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice.
 *
 * The defaults are asserted at length because almost every state this gate
 * measures is defined by contrast with the arrival state, and four of them are
 * easy to get backwards: the lab opens on the SESSION tab with the other four
 * panels not merely hidden but not yet RENDERED (`ensureRendered` is lazy); the
 * stepper opens on step 1 of 6 with a single card; the byte-display switch
 * opens ABBREVIATED, so every hex value on the page is elided; and the guided
 * tour is NOT running, so the tab strip carries no lesson-map ticks. A gate
 * that assumed any of those would be scanning one half of the lab twice.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // The `hidden` attribute is the ONLY thing hiding four of the five exhibits,
  // and the UA rule that implements it (`[hidden] { display: none }`) has
  // specificity (0,1,0) — the same as a class, so any later author rule with a
  // `display` beats it silently. `.tour-bar` has `display: grid` and is hidden
  // by the attribute, which is exactly that collision. `style.css` answers it
  // with `#app [hidden] { display: none !important }`; this asserts the answer
  // still works rather than trusting the comment above it.
  expect(
    await page.evaluate(() => {
      const probe = document.createElement('div');
      probe.className = 'tour-bar';
      probe.hidden = true;
      document.getElementById('app')!.append(probe);
      const d = getComputedStyle(probe).display;
      probe.remove();
      return d;
    }),
    'the hidden attribute must beat every author display rule inside #app'
  ).toBe('none');

  // Every exhibit is mounted by `src/main.ts`, so a navigation that resolves
  // proves nothing. The session panel is the only one rendered on arrival.
  await expect(page.locator('#tab-session')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#panel-session')).toBeVisible();
  for (const id of ['keyagg', 'rogue', 'nonce', 'vectors']) {
    await expect(page.locator(`#panel-${id}`)).toBeHidden();
    await expect(page.locator(`#panel-${id}`)).toBeEmpty();
  }

  // ── The stepper opens on one card of six ─────────────────────────────────
  await expect(page.locator('#panel-session .step-progress')).toHaveText('Step 1 of 6');
  await expect(page.locator('#panel-session .step-card')).toHaveCount(1);
  await expect(page.locator('#signer-count')).toHaveValue('3');
  await expect(page.locator('#sort-keys')).toBeChecked();

  // ── The tour is off, so the tab strip is a tab strip ─────────────────────
  await expect(page.locator('#tour-invite')).toBeVisible();
  await expect(page.locator('#tour-bar')).toBeHidden();
  await expect(page.locator('.tab-tick')).toHaveCount(0);
  await expect(page.locator('#panel-session .predict-status')).toBeEmpty();

  // The prediction group is a single-select whose state has to be a property of
  // the controls, not of a class name — four buttons, none pressed.
  await expect(page.locator('#panel-session .predict-opt[aria-pressed="false"]')).toHaveCount(4);
  await expect(page.locator('.predict-opt[aria-pressed="true"]')).toHaveCount(0);

  // ── Hex is abbreviated, and every value on the page is therefore elided ──
  await expect(page.getByRole('button', { name: 'Abbreviated' })).toHaveAttribute(
    'aria-pressed',
    'true'
  );
  await expect(page.getByRole('button', { name: 'Full bytes' })).toHaveAttribute(
    'aria-pressed',
    'false'
  );

  // ── Every disclosure ships shut ─────────────────────────────────────────
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and the gate this
 * replaces had no viewport narrower than 1280 — so the whole success criterion
 * was untested. This page is the shape that breaks it: 64-character hex values
 * everywhere, a 460px-square SVG plot, a four-column collapse diagram, a
 * two-column signature comparison, and seven tables of BIP-327 vectors. Each
 * table is meant to scroll inside its own `.table-wrap`; the assertion here is
 * that none of them scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. This page
    // has a decoy behind every `.table-wrap`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * `dom.ts`'s `scrollRegion()` builds every intended one with `role="region"`,
 * `tabindex="0"` and an `aria-label`. The assertion stays because that helper
 * is a convention rather than an enforcement, and because at 380px the set of
 * things that scroll is not the set of things anyone designed to scroll — a
 * panel narrow enough finds overflow in places a 1280px layout never does.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/** Run an assertion that throws, recording rather than throwing when collecting. */
async function soft(label: string, fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(`${label}\n  ${String(e).slice(0, 8000)}`);
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node.
 *
 * It ratchets rather than merely logging: anything NOT in the baseline fails,
 * anything in the baseline that got WORSE fails, and anything in the baseline
 * that has been FIXED fails until its entry is deleted. That last rule is what
 * stops the allowlist becoming a permanent exemption. The goal state is an
 * empty baseline, and this lab is one entry away from it — see
 * `nontext-baseline.ts`.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${f.detail}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  if (process.env.NT_BASELINE_CAPTURE) {
    expect(
      'NT_BASELINE_CAPTURE was set',
      'a capture run is not a passing gate — unset NT_BASELINE_CAPTURE'
    ).toBe('');
  }
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Six assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus the four landmark
 *    best-practice rules in `EXTRA_RULES`, merged from a SECOND axe run. See
 *    `analyzeAll` for why a second run rather than a second builder call.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result axe
 *    simply could not finish — including `aria-prohibited-attr`, where an
 *    `aria-label` on a role-less element hides, a defect that never reaches
 *    `violations` at all. This lab puts `aria-label` on eight role-less-by-
 *    default containers (`.collapse`, `.dep-chain`, `.preset-row`,
 *    `.input-row`, `.predict-opts`) and rescues each with `role="group"`; the
 *    role is one attribute away from being dropped by accident.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast and generated content — SC 1.4.11, which axe has no rule
 *    for; see `nontext.ts`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * Run axe twice and merge, because `withTags` and `withRules` CANNOT BE
 * COMBINED.
 *
 * Both write `options.runOnly`, so chaining them silently keeps only the last
 * one — `@axe-core/playwright`'s own docblock says "Cannot be used with
 * AxeBuilder#withTags" and the implementation is a plain overwrite. A
 * `.withTags(TAGS).withRules([...four landmark rules])` chain therefore runs
 * FOUR BEST-PRACTICE RULES AND NO WCAG RULES AT ALL, and reports a clean
 * `violations` array for a page with any number of WCAG failures on it.
 *
 * That is not a hypothetical: this gate was written that way, it passed, and it
 * kept passing when the curve plot's `aria-label` was emptied — an unmistakable
 * `svg-img-alt` failure — which is how the chain was found. Two analyses and a
 * merge is the only shape that runs both sets.
 */
async function analyzeAll(page: Page): Promise<{ violations: Result[]; incomplete: Result[] }> {
  const byTag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const byRule = await new AxeBuilder({ page }).withRules(EXTRA_RULES).analyze();
  return {
    violations: [...byTag.violations, ...byRule.violations],
    incomplete: [...byTag.incomplete, ...byRule.incomplete],
  };
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await analyzeAll(page);

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await soft(`non-text contrast in state: ${label}`, () =>
    expectNoNewNonTextFailures(page, label)
  );
  await soft(`scrollers in state: ${label}`, () => expectScrollersReachable(page, label));
  await soft(`reflow in state: ${label}`, () => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/** The first button inside `scope` whose visible text contains `label`. */
const btn = (page: Page, scope: string, label: string) =>
  page.locator(`${scope} button`, { hasText: label }).first();

/**
 * Open one `<details>` by clicking its summary, and assert it opened.
 *
 * Never `d.open = true`. The gate this replaces set `open` on every `<details>`
 * on the page from script, which both skipped the summary's own rendering and
 * produced a document with 56 vector cases expanded at once.
 */
async function openDetails(page: Page, selector: string): Promise<void> {
  const d = page.locator(selector).first();
  await d.locator('summary').first().click();
  await expect(d).toHaveAttribute('open', '');
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, AND IT IS MOSTLY EMPTY. Four of the
 *    five exhibits are not rendered at all until their tab is pressed, the
 *    stepper shows one card of six, and every hex value is elided. That is the
 *    state a reader meets and the gate this replaces never measured it — its
 *    only scan came after a drive that had unhidden all five panels at once.
 *
 *  - EVERY BRANCH OF EVERY FORK. Each of the three attacks renders in a broken
 *    mode and a fixed mode, and they are different colours: the broken one ends
 *    in `.verdict-alarm` (a successful forgery is an alarm, not a pass) and the
 *    fixed one in `.verdict-pass`. The rogue exhibit has a third branch — a
 *    malformed hand-supplied key, which is the only route to `.verdict-fail` in
 *    that panel. All eight are driven and scanned.
 *
 *  - THE EXTREMES OF EVERY INPUT, NOT THE DEFAULTS. `#signer-count` runs 2..5,
 *    `#keyagg-count` 1..6, `#nonce-honest-count` 1..4 and `#wagner-bits` 21..30,
 *    and each end changes how much content is on screen — which is a reflow
 *    question at 380px that only exists in a state a drive has to build.
 *
 *  - THE WRONG ANSWER AS WELL AS THE RIGHT ONE. `.match-bad` and `.pill-bad`
 *    are colour-bearing states reachable only by answering a learner check
 *    incorrectly, and `.match-ok` only by answering it correctly. Both are
 *    driven for both the exit questions and the four-row matching task.
 *
 *  - A REAL RESET. The tour's "Start over" calls `resetPredictions()` and
 *    re-renders every exhibit that has been rendered, from scratch. It is run
 *    after the whole lab has been populated, so the reset is scanned against
 *    the state it actually has to clear.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint — session step 1 of 6, four exhibits unrendered');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  // ── Exhibit 1: the signing session ──────────────────────────────────────
  const session = '#panel-session';

  // The prediction is asked BEFORE the reveal, and recorded without being
  // graded — a state with a live region populated and no verdict colour in it.
  const indist = page.locator('#panel-session .predict').first();
  await indist.locator('.predict-opt').first().click();
  await expect(indist.locator('.predict-status')).toContainText('recorded');
  await expect(indist.locator('.predict-opt[aria-pressed="true"]')).toHaveCount(1);
  await expect(indist.locator('.predict-opt.predict-chosen')).toHaveCount(1);
  await scanAt('indistinguishability prediction recorded, ungraded');

  await btn(page, session, 'Next step').click();
  await expect(page.locator(`${session} .step-progress`)).toHaveText('Step 2 of 6');
  await expect(page.locator(`${session} .step-card`)).toHaveCount(2);
  await scanAt('stepper at 2 of 6');

  await btn(page, session, 'Show all steps').click();
  await expect(page.locator(`${session} .step-card`)).toHaveCount(6);
  await expect(btn(page, session, 'Next step')).toBeDisabled();
  await expect(page.locator(`${session} .chip-agg`)).toHaveCount(3);
  await expect(page.locator(`${session} .aha .verdict-pass`).first()).toContainText(
    'signature valid'
  );
  await scanAt('all six steps revealed, collapse diagram complete, verifier accepts');

  // A disabled control is a real rendering with its own colours, and it is only
  // reachable here — "Next step" is enabled in every other state.
  await expect(btn(page, session, 'Next step')).toBeDisabled();

  await openDetails(page, `${session} details:has-text("Show the secret keys")`);
  await expect(page.locator(session)).toContainText('Never paste a real secret key');
  await scanAt('the secret-key disclosure open');

  await openDetails(page, `${session} .glossary`);
  await scanAt('the glossary open');

  // The blind lone-signer reveal: a live region filled with a per-property
  // comparison, every row identical.
  await btn(page, '#tour-blind', 'A was the group').click();
  await expect(page.locator('#tour-blind .guess-out')).toContainText('signers made together');
  await scanAt('lone-signer challenge answered and revealed');

  // Break it: one corrupted partial, attributed to its signer.
  await btn(page, session, 'Corrupt Signer 2').click();
  await expect(page.locator(`${session} .partial-bad`)).toHaveCount(1);
  await expect(page.locator(`${session} .break-it .break-out .verdict-fail`)).toContainText(
    'Signer 2'
  );
  await scanAt('one partial corrupted — the failing branch, in red');

  await btn(page, session, 'Try signing with one signer missing').click();
  await expect(page.locator(`${session} .break-it .break-out`)).toContainText('MuSig2 is n-of-n');
  await scanAt('n-of-n boundary refused');

  // Both ends of the signer slider. 5 is the most content this exhibit renders.
  await page.locator('#signer-count').fill('5');
  await btn(page, session, 'Show all steps').click();
  await expect(page.locator(`${session} .partial-row`)).toHaveCount(5);
  await scanAt('five signers — the widest collapse diagram');

  await page.locator('#signer-count').fill('2');
  await btn(page, session, 'Show all steps').click();
  await expect(page.locator(`${session} .partial-row`)).toHaveCount(2);
  await scanAt('two signers — the narrowest session');

  await page.locator('#sort-keys').uncheck();
  await btn(page, session, 'Show all steps').click();
  await expect(page.locator('#sort-keys')).not.toBeChecked();
  await scanAt('KeySort off — a different aggregate key');

  // Two different resets, and they are not interchangeable: "New keys" draws a
  // fresh signer set and jumps to the end, "Restart at step 1" keeps the keys
  // and collapses back to one card. Both clear a tampered partial.
  const aggBefore = await page.locator(`${session} .chip-agg`).first().textContent();
  await btn(page, session, 'New keys').click();
  await expect(page.locator(`${session} .step-card`)).toHaveCount(6);
  await expect(page.locator(`${session} .chip-agg`).first()).not.toHaveText(aggBefore ?? '');
  await scanAt('fresh keys — a new aggregate key, all steps revealed');

  await btn(page, session, 'Restart at step 1').click();
  await expect(page.locator(`${session} .step-progress`)).toHaveText('Step 1 of 6');
  await expect(page.locator(`${session} .step-card`)).toHaveCount(1);
  await expect(page.locator(`${session} .partial-bad`)).toHaveCount(0);
  await scanAt('restarted at step 1 — the stepper back to a single card');

  // ── The exit check, right answer and wrong answer ───────────────────────
  const exitQ = '#tour-transfer .exit-q';
  await page.locator(`${exitQ}`).first().locator('.check-opt').first().click();
  await expect(page.locator(exitQ).first().locator('.pill-ok')).toBeVisible();
  await scanAt('exit question answered correctly');

  await page.locator(exitQ).first().locator('.check-opt').nth(1).click();
  await expect(page.locator(exitQ).first().locator('.pill-bad')).toBeVisible();
  await scanAt('exit question answered incorrectly — the corrected state');

  const match = '#tour-transfer .match-task';
  const selects = page.locator(`${match} select`);
  await expect(selects).toHaveCount(4);
  for (let i = 0; i < 4; i++) await selects.nth(i).selectOption({ index: i + 1 });
  await page.locator(`${match} button`).click();
  await expect(page.locator(`${match} .pill-ok`)).toContainText('All four matched');
  await expect(page.locator('.mono-input.match-ok')).toHaveCount(4);
  await scanAt('matching task all correct — four green select borders');

  await selects.nth(2).selectOption({ index: 4 });
  await page.locator(`${match} button`).click();
  await expect(page.locator(`${match} .pill-bad`)).toBeVisible();
  await expect(page.locator('.mono-input.match-bad')).toHaveCount(1);
  await scanAt('matching task with one wrong row — the red select border');

  // ── Exhibit 2: key aggregation ──────────────────────────────────────────
  await page.locator('#tab-keyagg').click();
  const keyagg = '#panel-keyagg';
  await expect(page.locator(keyagg)).toBeVisible();
  await expect(page.locator(`${keyagg} .both-sides .verdict-pass`).first()).toContainText(
    'match exactly'
  );
  await expect(page.locator(`${keyagg} .curve-plot .cp-all circle`)).toHaveCount(126);
  await scanAt('key aggregation — the recomputation and the drawn group');

  await btn(page, keyagg, 'Reverse the order').click();
  await expect(page.locator(`${keyagg} .both-sides .verdict-pass`).first()).toBeVisible();
  await scanAt('key list reversed');

  await btn(page, keyagg, 'Make every key identical').click();
  await expect(page.locator(keyagg)).toContainText('all keys identical');
  await expect(page.locator(`${keyagg} .pill`, { hasText: 'second key → 1' })).toHaveCount(0);
  await scanAt('every key identical — the coefficient shortcut gone');

  await page.locator('#keyagg-count').fill('6');
  await expect(page.locator(`${keyagg} .both-sides .verdict-pass`).first()).toBeVisible();
  await scanAt('six keys — the longest coefficient table');

  await page.locator('#keyagg-count').fill('1');
  await expect(page.locator(`${keyagg} .both-sides .verdict-pass`).first()).toBeVisible();
  await scanAt('a single key — the degenerate aggregation');

  await btn(page, keyagg, 'Toggle the naive').click();
  await expect(page.locator(`${keyagg} .cp-naive`)).toHaveCount(0);
  await scanAt('the naive path hidden — a legend with one fewer key');

  await btn(page, keyagg, 'New points on the small curve').click();
  await expect(page.locator(`${keyagg} .curve-plot`)).toBeVisible();
  await scanAt('a fresh set of points on the small curve');

  // ── Exhibit 3: the rogue-key attack ─────────────────────────────────────
  await page.locator('#tab-rogue').click();
  const rogue = '#panel-rogue';
  await expect(page.locator(rogue)).toBeVisible();
  await expect(page.locator(`${rogue} .predict`)).toBeVisible();
  await scanAt('rogue-key exhibit before any attack has been run');

  await page.locator(`${rogue} .predict-opt`).first().click();
  await expect(page.locator(`${rogue} .predict-status`)).toContainText('Prediction recorded');
  await scanAt('rogue-key prediction recorded');

  await btn(page, rogue, 'Run the rogue-key attack').click();
  await expect(page.locator(`${rogue} .attack-broken .verdict-alarm`)).toContainText('Forged');
  await scanAt('rogue key forges against naive aggregation — the alarm branch');

  await btn(page, rogue, 'Run the same attack against BIP-327').click();
  await expect(page.locator(`${rogue} .attack-fixed .verdict-pass`)).toContainText('Attack failed');
  await expect(page.locator(`${rogue} .attack-fixed .pill`, { hasText: 'missed' })).toHaveCount(6);
  await scanAt('the same attack fails against BIP-327 — the pass branch');

  // The malformed-input branch: the only route to `.verdict-fail` in this panel.
  await page.locator('#rogue-key').fill('nonsense');
  await page.locator('#rogue-secret').fill('01');
  await btn(page, rogue, 'Submit to naive aggregation').click();
  await expect(page.locator(`${rogue} .attack-block`).last().locator('.verdict-fail')).toContainText(
    'Malformed input'
  );
  await scanAt('a malformed hand-supplied key refused');

  await btn(page, rogue, 'Solve for the rogue key').click();
  await expect(page.locator('#rogue-key')).not.toHaveValue('');
  await btn(page, rogue, 'Submit to naive aggregation').click();
  await expect(
    page.locator(`${rogue} .attack-block`).last().locator('.output').last().locator('.verdict-alarm')
  ).toContainText('Forged');
  await scanAt('a hand-supplied rogue key accepted by naive aggregation');

  await btn(page, rogue, 'Submit to BIP-327 aggregation').click();
  await expect(
    page.locator(`${rogue} .attack-block`).last().locator('.output').last().locator('.verdict-pass')
  ).toContainText('Attack failed');
  await scanAt('the same hand-supplied key rejected by BIP-327');

  // ── Exhibit 4: why two nonces ───────────────────────────────────────────
  await page.locator('#tab-nonce').click();
  const nonce = '#panel-nonce';
  await expect(page.locator(nonce)).toBeVisible();
  await expect(page.locator(`${nonce} .predict-debrief`).first()).toContainText(
    'did not record a prediction'
  );
  await scanAt('nonce exhibit before any attack, with an ungraded debrief');

  for (const opt of await page.locator(`${nonce} .predict-opt`).all()) await opt.click();
  await scanAt('both nonce predictions recorded');

  await btn(page, nonce, 'Steer the aggregate nonce').click();
  await expect(page.locator(`${nonce} .attack-broken .verdict-alarm`).first()).toContainText(
    'Nonce hijacked'
  );
  await scanAt('one nonce — the attacker hits the target exactly');

  await btn(page, nonce, 'Try the same trick against two nonces').click();
  await expect(page.locator(`${nonce} .grind-fixed .verdict-pass`)).toContainText('Attack failed');
  await scanAt('two nonces — every round misses');

  await page.locator('#nonce-honest-count').fill('4');
  await expect(page.locator('#nonce-honest-count')).toHaveValue('4');
  await btn(page, nonce, 'Steer the aggregate nonce').click();
  await expect(page.locator(`${nonce} .attack-broken .verdict-alarm`).first()).toBeVisible();
  await scanAt('four honest signers steered — the longest probe table');

  await openDetails(page, '#tour-advanced');
  await expect(page.locator('#tour-advanced table').first()).toContainText('Reduced parameter?');
  await scanAt('the advanced forgery disclosure open');

  // 21 bits rather than the shipped 27: the same attack, a search this gate can
  // afford to run four times over, and the branch that prints "21 bits".
  await page.locator('#wagner-bits').selectOption('21');
  await btn(page, nonce, 'Forge a signature nobody authorised').click();
  await expect(page.locator(`${nonce} .wagner-section .verdict-alarm`)).toContainText('Forged', {
    timeout: 120_000,
  });
  await expect(page.locator(`${nonce} .wagner-section .msg-forged`)).toHaveCount(1);
  await scanAt('Wagner forgery at 21 bits — a signature nobody authorised');

  await btn(page, nonce, 'Try to fix a target under two nonces').click();
  await expect(page.locator(`${nonce} .wagner-fixed .verdict-pass`).first()).toContainText(
    'No fixed target',
    { timeout: 120_000 }
  );
  await scanAt('Wagner against two nonces — no fixed target');

  await btn(page, nonce, 'Forge at full 256-bit width').click();
  await expect(page.locator(`${nonce} .ros-section .verdict-alarm`)).toContainText('Forged', {
    timeout: 180_000,
  });
  await expect(page.locator(`${nonce} .ros-section`)).toContainText('257');
  await scanAt('ROS forgery at full 256-bit width — nothing reduced');

  await btn(page, nonce, 'Run ROS against two nonces').click();
  await expect(
    page.locator(`${nonce} .ros-fixed .verdict-pass`, { hasText: 'Attack failed' })
  ).toBeVisible({ timeout: 180_000 });
  await expect(page.locator(`${nonce} .ros-fixed .both-sides .verdict-fail`)).toHaveCount(2);
  await scanAt('ROS against two nonces — the constant target is gone');

  // ── Exhibit 5: the BIP-327 vectors ──────────────────────────────────────
  await page.locator('#tab-vectors').click();
  const vectors = '#panel-vectors';
  await expect(page.locator(`${vectors} .kat-item`)).toHaveCount(56, { timeout: 60_000 });
  await expect(page.locator(`${vectors} .verdict-pass`).first()).toContainText('56 of 56');
  await scanAt('all 56 BIP-327 vectors run, in seven groups');

  await openDetails(page, `${vectors} .kat-item`);
  await expect(page.locator(`${vectors} .kat-item`).first()).toContainText(
    'This implementation produced'
  );
  await scanAt('one vector case expanded to expected vs. actual');

  // ── The global byte-display switch, in its other position ───────────────
  await page.getByRole('button', { name: 'Full bytes' }).click();
  await expect(page.getByRole('button', { name: 'Full bytes' })).toHaveAttribute(
    'aria-pressed',
    'true'
  );
  expect(
    await page
      .locator('[data-hex-full]')
      .evaluateAll((els) => els.filter((e) => e.textContent !== e.getAttribute('data-hex-full')).length),
    'full-bytes mode must expand every abbreviated value'
  ).toBe(0);
  await scanAt('full bytes — every 64-character hex value at full width');

  await page.locator('#tab-session').click();
  await expect(page.locator('#panel-session')).toBeVisible();
  await scanAt('back on the session exhibit, still in full bytes');

  // ── The guided tour: the tab strip becomes the lesson map ───────────────
  await btn(page, '#tour-invite', 'Start the guided tour').click();
  await expect(page.locator('#tour-bar')).toBeVisible();
  await expect(page.locator('.tour-label')).toContainText('Step 1 of 10');
  await expect(page.locator('.tour-dot-now')).toHaveCount(1);
  await scanAt('guided tour running, stop 1 of 10');

  for (let i = 0; i < 5; i++) await btn(page, '#tour-bar', 'Continue').click();
  await expect(page.locator('.tour-label')).toContainText('Step 6 of 10');
  await expect(page.locator('#tab-rogue')).toHaveClass(/tab-done/);
  await expect(page.locator('.tab-tick')).not.toHaveCount(0);
  await scanAt('tour stop 6 — finished exhibits ticked in the tab strip');

  for (let i = 0; i < 3; i++) await btn(page, '#tour-bar', 'Continue').click();
  await expect(page.locator('.tour-label')).toContainText('Step 9 of 10');
  await expect(page.locator('#tour-blind')).toBeVisible();
  await scanAt('tour stop 9 — the blind challenge the tour had to build');

  // The reset, run against a fully populated lab.
  await btn(page, '#tour-bar', 'Start over').click();
  await expect(page.locator('.tour-label')).toContainText('Step 1 of 10');
  await expect(page.locator('#panel-session .predict-status')).toBeEmpty();
  await expect(page.locator('#panel-session .step-progress')).toHaveText('Step 1 of 6');
  await scanAt('Start over — every exhibit re-rendered and predictions cleared');

  await btn(page, '#tour-bar', 'Exit tour').click();
  await expect(page.locator('#tour-invite')).toBeVisible();
  await expect(page.locator('.tab-tick')).toHaveCount(0);
  await scanAt('tour exited — the lesson map cleared');
}
