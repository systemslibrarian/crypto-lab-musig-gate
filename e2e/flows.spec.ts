/**
 * Functional end-to-end flows, asserted through roles and visible text.
 *
 * The unit suite proves the cryptography. These prove the *page* — that each
 * exhibit actually renders its result, that the alarm/pass semantics reach the DOM,
 * and that the interactions a learner is told to perform do what the copy claims.
 *
 * This is the layer that catches the class of bug unit tests structurally cannot:
 * a panel that throws on render, a verdict label that contradicts its own colour, a
 * control wired to nothing.
 *
 * Chromium-only by design — `deploy.yml` installs only Chromium, and these run
 * inside the same gate step, so adding a Firefox or WebKit project here would break
 * CI rather than strengthen it.
 */
import { expect, test, type Page } from '@playwright/test';

const noPageErrors = (page: Page): string[] => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  return errors;
};

const btn = (page: Page, scope: string, label: string) =>
  page.locator(`${scope} button`, { hasText: label }).first();

test.describe('the signing session', () => {
  test('steps through six stages and ends in a plain BIP-340 accept', async ({ page }) => {
    const errors = noPageErrors(page);
    await page.goto('.');

    // Starts at step 1 of 6, with only the first step card revealed.
    await expect(page.locator('#panel-session .step-progress')).toHaveText('Step 1 of 6');
    await expect(page.locator('#panel-session .step-card')).toHaveCount(1);

    await btn(page, '#panel-session', 'Next step').click();
    await expect(page.locator('#panel-session .step-progress')).toHaveText('Step 2 of 6');
    await expect(page.locator('#panel-session .step-card')).toHaveCount(2);

    await btn(page, '#panel-session', 'Show all steps').click();
    await expect(page.locator('#panel-session .step-card')).toHaveCount(6);
    // "Next step" is disabled at the end rather than silently doing nothing.
    await expect(btn(page, '#panel-session', 'Next step')).toBeDisabled();

    // The aha: the plain verifier accepted, and the independent one agreed.
    const aha = page.locator('#panel-session .aha').first();
    await expect(aha.locator('.verdict-pass').first()).toContainText('signature valid');
    await expect(aha).toContainText('the two implementations agree');

    expect(errors).toEqual([]);
  });

  test('stepping reveals more of the SAME session — the numbers do not change', async ({ page }) => {
    await page.goto('.');
    const keyOf = async () =>
      (await page.locator('#panel-session .chip-agg').first().textContent()) ?? '';
    await btn(page, '#panel-session', 'Next step').click(); // step 2 computes Q
    const afterStep2 = await keyOf();
    expect(afterStep2).not.toBe('');
    await btn(page, '#panel-session', 'Show all steps').click();
    expect(await keyOf()).toBe(afterStep2);
  });

  test('the collapse diagram ends with exactly one aggregate per row', async ({ page }) => {
    await page.goto('.');
    await btn(page, '#panel-session', 'Show all steps').click();
    // Three rows — keys, nonces, signatures — each collapsing to a single chip.
    await expect(page.locator('#panel-session .collapse-row')).toHaveCount(3);
    await expect(page.locator('#panel-session .chip-agg')).toHaveCount(3);
  });

  test('the signer count drives the number of partial signatures', async ({ page }) => {
    await page.goto('.');
    await page.locator('#signer-count').fill('5');
    await btn(page, '#panel-session', 'Show all steps').click();
    await expect(page.locator('#panel-session .partial-row')).toHaveCount(5);
    await expect(page.locator('#panel-session .partial-bad')).toHaveCount(0);
  });

  test('unticking KeySort changes the aggregate key', async ({ page }) => {
    await page.goto('.');
    await btn(page, '#panel-session', 'Show all steps').click();

    // KeySort only moves the aggregate key when it actually reorders the list. With
    // three random keys there is a ~1-in-6 chance they are already in order, in which
    // case an unchanged Q is CORRECT — so re-key until sorting is a real permutation
    // rather than asserting on a coin flip.
    const sortedOrder = async (): Promise<string[]> =>
      page.locator('#panel-session .step-card').first().locator('.field-label').allInnerTexts();
    const reordered = async (): Promise<boolean> => {
      const labels = (await sortedOrder()).filter((t) => t.startsWith('Signer '));
      return labels.join(',') !== [...labels].sort().join(',');
    };
    for (let i = 0; i < 12 && !(await reordered()); i++) {
      await btn(page, '#panel-session', 'New keys').click();
    }
    expect(await reordered()).toBe(true);

    const sorted = await page.locator('#panel-session .chip-agg').first().textContent();
    await page.locator('#sort-keys').uncheck();
    await btn(page, '#panel-session', 'Show all steps').click();
    const unsorted = await page.locator('#panel-session .chip-agg').first().textContent();
    expect(unsorted).not.toBe(sorted);
  });

  test('corrupting one partial signature names that signer and fails the signature', async ({ page }) => {
    await page.goto('.');
    await btn(page, '#panel-session', 'Show all steps').click();
    await btn(page, '#panel-session', 'Corrupt Signer 2').click();

    // Exactly one partial is marked rejected — the failure is attributable.
    await expect(page.locator('#panel-session .partial-bad')).toHaveCount(1);
    await expect(page.locator('#panel-session .partial-bad')).toContainText('partial REJECTED');
    await expect(
      page.locator('#panel-session .break-it .break-out .verdict-fail'),
    ).toContainText('Signer 2');
    // And the aggregate signature no longer verifies.
    await expect(page.locator('#panel-session .aha .verdict-fail').first()).toBeVisible();
  });

  test('signing with a signer missing is refused', async ({ page }) => {
    await page.goto('.');
    await btn(page, '#panel-session', 'Show all steps').click();
    await btn(page, '#panel-session', 'Try signing with one signer missing').click();
    const out = page.locator('#panel-session .break-it .break-out');
    await expect(out.locator('.verdict-fail')).toContainText('rejected');
    await expect(out).toContainText('MuSig2 is n-of-n');
  });

  test('the secret keys really are the keys behind the published ones', async ({ page }) => {
    await page.goto('.');
    const reveal = page.locator('#panel-session details', {
      hasText: 'Show the secret keys',
    }).first();
    await reveal.locator('summary').click();
    await expect(reveal).toContainText('d_1');
    await expect(reveal).toContainText('Never paste a real secret key');
  });
});

test.describe('the lone-signer challenge', () => {
  test('offers two indistinguishable signatures and reveals which was the group', async ({ page }) => {
    await page.goto('.');
    await btn(page, '#panel-session', 'Show all steps').click();
    const section = page.locator('#panel-session .aha', {
      hasText: 'One of these was signed by a group',
    });
    await expect(section.locator('.sig-card')).toHaveCount(2);
    // Both are accepted by the same verifier — that is the point.
    await expect(section.locator('.sig-card .verdict-pass')).toHaveCount(2);
    await expect(section.locator('.verdict-pass', { hasText: 'Indistinguishable' })).toBeVisible();

    await section.locator('button', { hasText: 'A was the group' }).click();
    await expect(section.locator('.guess-out')).toContainText('signers made together');
    // Every compared property must read "identical".
    const differs = await section.locator('.pill-bad', { hasText: 'differs' }).count();
    expect(differs).toBe(0);
  });
});

test.describe('key aggregation', () => {
  test('recomputes Σ a_i·P_i and matches it against Q', async ({ page }) => {
    const errors = noPageErrors(page);
    await page.goto('.');
    await page.locator('#tab-keyagg').click();
    const panel = page.locator('#panel-keyagg');
    await expect(panel.locator('.both-sides .verdict-pass').first()).toContainText('match exactly');
    // Exactly one key gets the coefficient-1 shortcut.
    await expect(panel.locator('.pill', { hasText: 'second key → 1' })).toHaveCount(1);
    expect(errors).toEqual([]);
  });

  test('reversing the key order changes the aggregate key', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-keyagg').click();
    const q = page.locator('#panel-keyagg .field', { hasText: 'Q from KeyAgg' }).locator('code');
    const before = await q.textContent();
    await btn(page, '#panel-keyagg', 'Reverse the order').click();
    await expect(q).not.toHaveText(before ?? '');
  });

  test('making every key identical removes the shortcut entirely', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-keyagg').click();
    await btn(page, '#panel-keyagg', 'Make every key identical').click();
    const panel = page.locator('#panel-keyagg');
    await expect(panel.locator('.pill', { hasText: 'second key → 1' })).toHaveCount(0);
    await expect(panel).toContainText('all keys identical');
    // The Σ a_i·P_i check must still hold in this edge case.
    await expect(panel.locator('.both-sides .verdict-pass')).toBeVisible();
  });
});

test.describe('the rogue-key attack', () => {
  test('succeeds against naive aggregation and is shown as an ALARM', async ({ page }) => {
    const errors = noPageErrors(page);
    await page.goto('.');
    await page.locator('#tab-rogue').click();
    await btn(page, '#panel-rogue', 'Run the rogue-key attack').click();

    const broken = page.locator('#panel-rogue .attack-broken');
    // Colour tracks system integrity: a successful forgery is an alarm, not a pass.
    await expect(broken.locator('.verdict-alarm')).toContainText('Forged');
    await expect(broken.locator('.verdict-pass')).toHaveCount(0);
    await expect(broken).toContainText('discrete log: yes');
    expect(errors).toEqual([]);
  });

  test('fails against BIP-327, with every fixed-point round missing', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-rogue').click();
    await btn(page, '#panel-rogue', 'Run the same attack against BIP-327').click();

    const fixed = page.locator('#panel-rogue .attack-fixed');
    await expect(fixed.locator('.verdict-pass')).toContainText('Attack failed');
    await expect(fixed.locator('.verdict-alarm')).toHaveCount(0);
    await expect(fixed.locator('.pill', { hasText: 'HIT' })).toHaveCount(0);
    await expect(fixed.locator('.pill', { hasText: 'missed' })).toHaveCount(6);
    await expect(fixed).toContainText('aggregate key: no');
  });

  test('a hand-supplied rogue key is accepted by naive and rejected by BIP-327', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-rogue').click();
    await btn(page, '#panel-rogue', 'Solve for the rogue key').click();
    await expect(page.locator('#rogue-key')).not.toHaveValue('');

    await btn(page, '#panel-rogue', 'Submit to naive aggregation').click();
    let out = page.locator('#panel-rogue .attack-block').last().locator('.output').last();
    await expect(out.locator('.verdict-alarm')).toContainText('Forged');

    await btn(page, '#panel-rogue', 'Submit to BIP-327 aggregation').click();
    out = page.locator('#panel-rogue .attack-block').last().locator('.output').last();
    await expect(out.locator('.verdict-pass')).toContainText('Attack failed');
  });

  test('a malformed rogue key is refused before any signing happens', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-rogue').click();
    await page.locator('#rogue-key').fill('nonsense');
    await page.locator('#rogue-secret').fill('01');
    await btn(page, '#panel-rogue', 'Submit to naive aggregation').click();
    const out = page.locator('#panel-rogue .attack-block').last().locator('.output').last();
    await expect(out.locator('.verdict-fail')).toContainText('Malformed input');
    await expect(out).toContainText('not a defence');
  });
});

test.describe('why two nonces', () => {
  test('a single nonce lets the attacker hit its target exactly', async ({ page }) => {
    const errors = noPageErrors(page);
    await page.goto('.');
    await page.locator('#tab-nonce').click();
    await btn(page, '#panel-nonce', 'Steer the aggregate nonce').click();

    const broken = page.locator('#panel-nonce .attack-broken');
    await expect(broken.locator('.verdict-alarm')).toContainText('Nonce hijacked');
    // Target and achieved must be the SAME value — that is the whole demonstration.
    const target = await broken
      .locator('.field', { hasText: 'Target aggregate nonce' })
      .locator('code')
      .textContent();
    const achieved = await broken
      .locator('.field', { hasText: 'Aggregate nonce actually produced' })
      .locator('code')
      .textContent();
    expect(achieved).toBe(target);
    expect(errors).toEqual([]);
  });

  test('two nonces make the same move miss every round', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-nonce').click();
    await btn(page, '#panel-nonce', 'Try the same trick against two nonces').click();

    const fixed = page.locator('#panel-nonce .attack-fixed');
    await expect(fixed.locator('.verdict-pass')).toContainText('Attack failed');
    await expect(fixed.locator('.pill', { hasText: 'HIT' })).toHaveCount(0);
    const target = await fixed
      .locator('.field', { hasText: 'Target aggregate nonce' })
      .locator('code')
      .textContent();
    const achieved = await fixed
      .locator('.field', { hasText: 'Aggregate nonce actually produced' })
      .locator('code')
      .textContent();
    expect(achieved).not.toBe(target);
  });

  test('is explicit about the part of the forgery it does not run', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-nonce').click();
    const scope = page.locator('#panel-nonce details', { hasText: 'What this shows' });
    await scope.locator('summary').click();
    await expect(scope).toContainText('Wagner');
    await expect(scope).toContainText('ROS');
    await expect(scope).toContainText('reduced');
  });
});

test.describe('the drawable group', () => {
  test('plots the real 127-element curve with a text alternative', async ({ page }) => {
    const errors = noPageErrors(page);
    await page.goto('.');
    await page.locator('#tab-keyagg').click();
    const plot = page.locator('#panel-keyagg .curve-plot');
    await expect(plot).toBeVisible();
    // All 126 affine points must be drawn — a partial scatter would misrepresent the group.
    await expect(plot.locator('.cp-all circle')).toHaveCount(126);
    await expect(plot).toHaveAttribute('role', 'img');
    const alt = await plot.getAttribute('aria-label');
    expect(alt).toContain('126 points');
    expect(alt).toContain('aggregate key Q');
    // The numbers behind the picture are also present as a table.
    await expect(page.locator('#panel-keyagg .curve-section table tbody tr')).toHaveCount(3);
    expect(errors).toEqual([]);
  });

  test('is explicit that it is the discrete group, not the textbook curve', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-keyagg').click();
    const section = page.locator('#panel-keyagg .curve-section');
    await expect(section).toContainText('not the smooth curve from textbooks');
    await expect(section).toContainText('no security at all');
  });

  test('the naive path can be toggled off', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-keyagg').click();
    await expect(page.locator('#panel-keyagg .cp-naive')).toHaveCount(1);
    await btn(page, '#panel-keyagg', 'Toggle the naive').click();
    await expect(page.locator('#panel-keyagg .cp-naive')).toHaveCount(0);
  });
});

test.describe('the Wagner forgery', () => {
  test('forges a signature on a message the honest signer never saw', async ({ page }) => {
    const errors = noPageErrors(page);
    await page.goto('.');
    await page.locator('#tab-nonce').click();
    await btn(page, '#panel-nonce', 'Forge a signature nobody authorised').click();

    const section = page.locator('#panel-nonce .wagner-section');
    // The attack must SUCCEED, and read as an alarm rather than a success.
    await expect(section.locator('.verdict-alarm')).toContainText('Forged', { timeout: 60_000 });
    await expect(section.locator('.verdict-alarm')).toContainText('never saw');
    await expect(section).toContainText('confirmed');
    // Σ e_j must equal e* exactly — the k-sum is the whole attack.
    await expect(section.locator('.both-sides .verdict-pass')).toContainText('match exactly');
    // Four sessions queried, one forged message.
    await expect(section.locator('.msg-list').first().locator('li')).toHaveCount(4);
    await expect(section.locator('.msg-forged')).toHaveCount(1);
    // And it says plainly what the same attack costs unreduced.
    await expect(section).toContainText('2^85');
    expect(errors).toEqual([]);
  });

  test('works at a narrower search width too', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-nonce').click();
    await page.locator('#wagner-bits').selectOption('21');
    await btn(page, '#panel-nonce', 'Forge a signature nobody authorised').click();
    const section = page.locator('#panel-nonce .wagner-section');
    await expect(section.locator('.verdict-alarm')).toContainText('Forged', { timeout: 60_000 });
    await expect(section).toContainText('21 bits');
  });

  test('the same attack against two nonces cannot fix a target', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-nonce').click();
    await btn(page, '#panel-nonce', 'Try to fix a target under two nonces').click();

    const section = page.locator('#panel-nonce .attack-fixed').last();
    await expect(section.locator('.verdict-pass').first()).toContainText('No fixed target');
    // Every probed nonce assignment produced a different target.
    const rows = section.locator('table tbody tr');
    await expect(rows).toHaveCount(5);
    const targets = await section.locator('table tbody tr td:last-child code').allTextContents();
    expect(new Set(targets).size).toBe(targets.length);
    // The completed attempt is rejected by the same verifier.
    await expect(section.locator('.verdict-pass', { hasText: 'Attack failed' })).toBeVisible();
    await expect(section.locator('.verdict-alarm')).toHaveCount(0);
  });

  test('is honest about what it does not cover', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-nonce').click();
    const scope = page.locator('#panel-nonce details', { hasText: 'What this shows' });
    await scope.locator('summary').click();
    await expect(scope).toContainText('asserted rather than proven');
    await expect(scope).toContainText('ROS');
  });
});

test.describe('the BIP-327 vectors', () => {
  test('run in the browser and all pass', async ({ page }) => {
    const errors = noPageErrors(page);
    await page.goto('.');
    await page.locator('#tab-vectors').click();
    const panel = page.locator('#panel-vectors');

    await expect(panel.locator('.verdict-pass').first()).toContainText('56 of 56');
    await expect(panel.locator('.kat-item')).toHaveCount(56);
    await expect(panel.locator('.kat-bad')).toHaveCount(0);
    // One group per spec vector file, each reporting a full pass.
    await expect(panel.locator('.kat-group')).toHaveCount(7);
    await expect(panel.locator('.kat-group .pill-bad')).toHaveCount(0);
    expect(errors).toEqual([]);
  });

  test('each case exposes expected vs. actual, not just a tick', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-vectors').click();
    const first = page.locator('#panel-vectors .kat-item').first();
    await first.locator('summary').click();
    await expect(first).toContainText('Expected');
    await expect(first).toContainText('This implementation produced');
  });
});

test.describe('chrome and navigation', () => {
  test('the theme toggle flips the document theme and persists it', async ({ page }) => {
    await page.goto('.');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await page.locator('#cl-theme-toggle').click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  });

  test('there is exactly one h1 and one banner landmark', async ({ page }) => {
    await page.goto('.');
    await expect(page.locator('h1')).toHaveCount(1);
    await expect(page.locator('h1')).toHaveText('MuSig Gate');
    await expect(page.locator('[role="banner"]')).toHaveCount(1);
  });

  test('tabs are keyboard-navigable with arrow keys', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-session').focus();
    await page.keyboard.press('ArrowRight');
    await expect(page.locator('#tab-keyagg')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#panel-keyagg')).toBeVisible();
    await page.keyboard.press('End');
    await expect(page.locator('#tab-vectors')).toHaveAttribute('aria-selected', 'true');
  });

  test('a deep link opens its exhibit directly', async ({ page }) => {
    await page.goto('./#rogue');
    await expect(page.locator('#tab-rogue')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#panel-rogue')).toBeVisible();
    await expect(page.locator('#panel-session')).toBeHidden();
  });

  test('the scripture footer is present verbatim, exactly once', async ({ page }) => {
    await page.goto('.');
    const line =
      'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31';
    await expect(page.getByText(line, { exact: true })).toHaveCount(1);
  });

  test('nothing overflows horizontally on a narrow viewport', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await page.goto('.');
    await btn(page, '#panel-session', 'Show all steps').click();
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(0);
  });
});
