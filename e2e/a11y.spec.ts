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
 * failure paths, and opens every disclosure, glossary and learner check so the
 * feedback live regions are populated too.
 */
async function driveDemos(page: Page): Promise<void> {
  const click = async (selector: string, nth = 0): Promise<void> => {
    await page
      .locator(selector)
      .nth(nth)
      .click({ timeout: 3000 })
      .catch(() => {});
  };

  // --- Exhibit 1: the signing session, stepped to the end and then broken ----
  await click('#tab-session');
  await page.locator('#panel-session').waitFor({ timeout: 10_000 });
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
  await clickByText(page, '#panel-nonce', 'Steer the aggregate nonce');
  await clickByText(page, '#panel-nonce', 'Try the same trick against two nonces');
  await clickByText(page, '#panel-nonce', 'New target nonce');
  await clickByText(page, '#panel-nonce', 'Steer the aggregate nonce');
  await clickByText(page, '#panel-nonce', 'Try the same trick against two nonces');
  // The Wagner forgery: a narrow width keeps the scan fast, and the select itself
  // needs exercising since a styled <select> is its own a11y hazard.
  await page.locator('#wagner-bits').selectOption('21').catch(() => {});
  await clickByText(page, '#panel-nonce', 'Forge a signature nobody authorised');
  await page
    .locator('#panel-nonce .wagner-section .verdict')
    .first()
    .waitFor({ timeout: 60_000 })
    .catch(() => {});
  await clickByText(page, '#panel-nonce', 'Try to fix a target under two nonces');
  // The full-width ROS forgery and its two-nonce counterpart.
  await clickByText(page, '#panel-nonce', 'Forge at full 256-bit width');
  await page
    .locator('#panel-nonce .ros-section .verdict')
    .first()
    .waitFor({ timeout: 60_000 })
    .catch(() => {});
  await clickByText(page, '#panel-nonce', 'Run ROS against two nonces');
  await page.waitForTimeout(150);

  // --- Exhibit 5: the BIP-327 vectors (renders on first activation) ---------
  await click('#tab-vectors');
  await page.locator('#panel-vectors').waitFor({ timeout: 15_000 });
  await page.waitForTimeout(300);

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

/** Click the first button inside `scope` whose visible text starts with `label`. */
async function clickByText(page: Page, scope: string, label: string): Promise<void> {
  const btn = page.locator(`${scope} button`, { hasText: label }).first();
  await btn.click({ timeout: 3000 }).catch(() => {});
  await page.waitForTimeout(60);
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
