import { expect, test } from '@playwright/test';
import {
  NARROW,
  boot,
  driveAllStates,
  expectBaselineNotStale,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * The WCAG 2.1 A/AA gate: {dark, light} × {1280 desktop, 380 phone}.
 *
 * Four configurations rather than two, because the gate this replaces ran only
 * at the project's default 1280x720 and so never tested WCAG 1.4.10 (Reflow) at
 * all — and because a defect that only exists in one theme at one width is the
 * normal case, not the exception. See `gate.ts` for what the previous spec
 * actually did and why each of its five shortcuts turned a failure into a pass.
 *
 * Every configuration runs the SAME drive. `driveAllStates` walks all five
 * exhibits, both branches of all three attacks plus the rogue exhibit's
 * malformed-input branch, both ends of all four numeric inputs, the right and
 * wrong answer to both learner checks, both positions of the byte-display
 * switch, the guided tour's lesson-map state, and the "Start over" reset — and
 * scans after every one of them.
 */
const CONFIGS = [
  { theme: 'dark' as const, width: 1280, height: 800, label: 'dark / 1280px' },
  { theme: 'dark' as const, ...NARROW, label: 'dark / 380px' },
];

for (const cfg of CONFIGS) {
  test(`WCAG 2.1 A/AA — ${cfg.label}`, async ({ page }) => {
    // The whole lab, scanned in ~45 states, including a full-width ROS forgery
    // over 256 sessions. The budget is the drive's, not any one assertion's.
    test.setTimeout(1_500_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize({ width: cfg.width, height: cfg.height });
    await boot(page, cfg.theme);
    await driveAllStates(page, cfg.label);
    expectBaselineNotStale();
    expect(errors, 'no page or console errors during the drive').toEqual([]);
    reportCollected();
  });
}
