import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Put EVERY exhibit into its post-interaction state before scanning.
 *
 * Axe only checks what is in the DOM, and this lab renders each tab lazily and
 * fills dynamic result regions on click — so an unscanned state is an ungated
 * state. This driver walks all five exhibits, steps the signing session to its
 * final step, answers the blind lone-signer challenge both ways, fires every attack
 * — rogue-key, nonce steering, Wagner and ROS — in both its broken and fixed mode, runs the hand-supplied rogue-key path
 * (including its malformed-input rejection), trips the tamper and drop-a-signer
 * failure paths, flips the byte-display switch to full width, and opens every
 * disclosure, glossary and learner check so the feedback live regions are populated
 * too.
 */
async function driveDemos(page: Page): Promise<void> {
  const click = async (selector: string, nth = 0): Promise<void> => {
    await page
      .locator(selector)
      .nth(nth)
      .click({ timeout: 3000 })
      .catch(() => {});
  };

  // --- The guided tour: its bar, progress and cross-tab jumps are real UI ----
  await clickByText(page, '#tour-invite', 'Start the guided tour');
  await page.waitForTimeout(120);
  await clickByText(page, '#tour-bar', 'Continue');
  await clickByText(page, '#tour-bar', 'Continue');
  await clickByText(page, '#tour-bar', 'Exit tour');
  await page.waitForTimeout(120);

  // --- Exhibit 1: the signing session, stepped to the end and then broken ----
  await click('#tab-session');
  await page.locator('#panel-session').waitFor({ timeout: 10_000 });
  // The indistinguishability prediction sits before the stepper.
  for (const el of await page.locator('#panel-session .predict-opt').all()) {
    await el.click({ timeout: 1500 }).catch(() => {});
  }
  // Step forward a few times so intermediate step cards get scanned, then reveal all.
  for (let i = 0; i < 3; i++) await clickByText(page, '#panel-session', 'Next step');
  await clickByText(page, '#panel-session', 'Show all steps');
  await page.waitForTimeout(150);
  // Untick KeySort (changes Q) and exercise the range input.
  await page.locator('#sort-keys').click({ timeout: 3000 }).catch(() => {});
  await page.locator('#signer-count').fill('4').catch(() => {});
  await page.locator('#signer-count').press('ArrowLeft').catch(() => {});
  await clickByText(page, '#panel-session', 'Show all steps');
  // The blind lone-signer pair: populate the reveal live region (both outcomes are
  // reachable since the correct slot is a coin flip, so click both buttons).
  await clickByText(page, '#panel-session', 'A was the group');
  await clickByText(page, '#panel-session', 'B was the group');
  // Break-it paths: attribute a corrupted partial, then the n-of-n boundary.
  await clickByText(page, '#panel-session', 'Corrupt Signer 2');
  await clickByText(page, '#panel-session', 'Try signing with one signer missing');
  await page.waitForTimeout(150);

  // The exit check: both scenario questions and the matching task, including its
  // wrong-answer styling, which is a colour-bearing state the gate must see.
  for (const el of await page.locator('#tour-transfer .check-opt').all()) {
    await el.click({ timeout: 1500 }).catch(() => {});
  }
  const selects = await page.locator('#tour-transfer .match-task select').all();
  for (let i = 0; i < selects.length; i++) {
    // Deliberately misalign one row so both match-ok and match-bad are rendered.
    await selects[i].selectOption({ index: i === 0 ? 2 : i + 1 }).catch(() => {});
  }
  await clickByText(page, '#tour-transfer', 'Check my answers');
  await page.waitForTimeout(150);

  // --- Exhibit 2: key aggregation ------------------------------------------
  await click('#tab-keyagg');
  await page.locator('#panel-keyagg').waitFor({ timeout: 10_000 });
  for (const label of ['Reverse the order', 'Apply KeySort', 'Make every key identical', 'New key set']) {
    await clickByText(page, '#panel-keyagg', label);
  }
  await page.locator('#keyagg-count').fill('1').catch(() => {});
  await page.locator('#keyagg-count').press('ArrowRight').catch(() => {});
  // The drawable-group plot, in both of its states.
  await clickByText(page, '#panel-keyagg', 'New points on the small curve');
  await clickByText(page, '#panel-keyagg', 'Toggle the naive');
  await clickByText(page, '#panel-keyagg', 'Toggle the naive');
  for (const el of await page.locator('#panel-rogue .predict-opt').all()) {
    await el.click({ timeout: 1500 }).catch(() => {});
  }
  await page.waitForTimeout(150);

  // --- Exhibit 3: the rogue-key attack, both modes + the manual path --------
  await click('#tab-rogue');
  await page.locator('#panel-rogue').waitFor({ timeout: 10_000 });
  await clickByText(page, '#panel-rogue', 'Run the rogue-key attack');
  await clickByText(page, '#panel-rogue', 'Run the same attack against BIP-327');
  // The malformed-input rejection state first, then the solved-for-you state.
  await page.locator('#rogue-key').fill('not-a-key').catch(() => {});
  await clickByText(page, '#panel-rogue', 'Submit to naive aggregation');
  await clickByText(page, '#panel-rogue', 'Solve for the rogue key');
  await clickByText(page, '#panel-rogue', 'Submit to naive aggregation');
  await clickByText(page, '#panel-rogue', 'Submit to BIP-327 aggregation');
  await page.waitForTimeout(150);

  // --- Exhibit 4: why two nonces -------------------------------------------
  await click('#tab-nonce');
  await page.locator('#panel-nonce').waitFor({ timeout: 10_000 });
  // Answer both predictions so their recorded state and their debriefs get scanned.
  for (const el of await page.locator('#panel-nonce .predict-opt').all()) {
    await el.click({ timeout: 1200 }).catch(() => {});
  }
  await clickByText(page, '#panel-nonce', 'Steer the aggregate nonce');
  await clickByText(page, '#panel-nonce', 'Try the same trick against two nonces');
  await clickByText(page, '#panel-nonce', 'New target nonce');
  await clickByText(page, '#panel-nonce', 'Steer the aggregate nonce');
  await clickByText(page, '#panel-nonce', 'Try the same trick against two nonces');

  // The two forgeries are advanced material behind a disclosure. It MUST be opened
  // before driving them: otherwise every click below waits out its timeout against a
  // hidden button, the scan never reaches those states, and the whole spec times out.
  await page.locator('#tour-advanced > summary').click({ timeout: 3000 }).catch(() => {});
  // A narrow width keeps the scan fast, and the styled <select> is its own hazard.
  await page.locator('#wagner-bits').selectOption('21').catch(() => {});
  await clickByText(page, '#panel-nonce', 'Forge a signature nobody authorised');
  await page
    .locator('#panel-nonce .wagner-section .verdict')
    .first()
    .waitFor({ timeout: 30_000 })
    .catch(() => {});
  await clickByText(page, '#panel-nonce', 'Try to fix a target under two nonces');
  // The full-width ROS forgery and its two-nonce counterpart.
  await clickByText(page, '#panel-nonce', 'Forge at full 256-bit width');
  await page
    .locator('#panel-nonce .ros-section .verdict')
    .first()
    .waitFor({ timeout: 30_000 })
    .catch(() => {});
  await clickByText(page, '#panel-nonce', 'Run ROS against two nonces');
  await page.waitForTimeout(150);

  // --- Exhibit 5: the BIP-327 vectors (renders on first activation) ---------
  await click('#tab-vectors');
  await page.locator('#panel-vectors').waitFor({ timeout: 15_000 });
  await page.waitForTimeout(300);

  // Full bytes: the wider, harder layout for every hex value on the page, and the
  // other pressed state of the byte-display switch. Flipped here rather than at the
  // start so the scan sees full-width values in every exhibit at once.
  await clickByText(page, '.byte-mode', 'Full bytes');

  // The tab strip's lesson-map state exists only while the tour is running, so put
  // the tour back and advance far enough that a completed-exhibit tick — a coloured
  // tab plus visually-hidden text — is in the DOM to be scanned.
  await clickByText(page, '#tour-invite', 'Start the guided tour');
  for (let i = 0; i < 5; i++) await clickByText(page, '#tour-bar', 'Continue');

  // Reveal every panel and open every disclosure so all states are in the DOM.
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
    document.querySelectorAll<HTMLElement>('[hidden]').forEach((el) => el.removeAttribute('hidden'));
  });
  // Now that everything is visible, populate every learner-check live region —
  // both the correct and the incorrect feedback styling.
  for (const el of await page.locator('.check-opt').all()) {
    await el.click({ timeout: 1500, force: true }).catch(() => {});
  }
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });
  await page.waitForTimeout(250);
}

/**
 * Click the first button inside `scope` whose visible text starts with `label`.
 *
 * Visibility is checked first so a button that is absent or collapsed costs
 * milliseconds rather than a full click timeout. With this many exploratory clicks
 * the difference is the whole spec's runtime budget.
 */
async function clickByText(page: Page, scope: string, label: string): Promise<void> {
  const btn = page.locator(`${scope} button`, { hasText: label }).first();
  if (!(await btn.isVisible().catch(() => false))) return;
  await btn.click({ timeout: 2000 }).catch(() => {});
  await page.waitForTimeout(50);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([]);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await driveDemos(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await scan(page);
});
