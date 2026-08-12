/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * Every finding inside `#app` — this lab's own markup — has been fixed, and the
 * two entries below are the whole remainder. Both are in the SHARED CRYPTO LAB
 * TOP BAR, the block of markup and CSS that every repo in this fleet carries a
 * byte-identical copy of. `.cl-btn` draws its edge as
 * `color-mix(in srgb, var(--accent) 38%, transparent)` over the bar's fixed
 * `#0b1512`, which resolves to rgb(88,59,39) here and measures 1.83:1 against
 * that background — in BOTH themes, because the bar is always dark. It is
 * reported upward as a fleet-wide observation rather than patched in one repo,
 * because a one-repo edit to the shared header is exactly the drift this fleet's
 * conventions forbid; when the shared block is fixed, these two entries stop
 * appearing and the ratchet will fail until they are deleted, which is the
 * intended way to find out.
 *
 * Note there is no `--accent`-sensitivity here to be careless with: this lab's
 * fix for its own accent-on-light failures introduced `--accent-strong` and left
 * `--accent` untouched precisely so these numbers did not move. Darkening
 * `--accent` would have taken the light-theme `.cl-btn` edge from 1.83:1 to
 * 1.50:1 — making a defect this repo cannot fix measurably worse.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  // The shared bar's Menu and GitHub controls, `<a class="cl-btn">`.
  'control-boundary|a.cl-btn': { ratio: 1.83, required: 3, unverified: false },
  // The shared bar's theme toggle, the same `.cl-btn` edge on a <button>.
  'control-boundary|button#cl-theme-toggle.cl-btn.cl-icon': {
    ratio: 1.83,
    required: 3,
    unverified: false,
  },
};
