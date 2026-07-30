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

    const fixed = page.locator('#panel-nonce .grind-fixed');
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
  /** Both forgeries are advanced material now, behind a disclosure by default. */
  test.beforeEach(async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-nonce').click();
    await page.locator('#tour-advanced > summary').click();
  });

  test('forges a signature on a message the honest signer never saw', async ({ page }) => {
    const errors = noPageErrors(page);
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
    await page.locator('#wagner-bits').selectOption('21');
    await btn(page, '#panel-nonce', 'Forge a signature nobody authorised').click();
    const section = page.locator('#panel-nonce .wagner-section');
    await expect(section.locator('.verdict-alarm')).toContainText('Forged', { timeout: 60_000 });
    await expect(section).toContainText('21 bits');
  });

  test('the same attack against two nonces cannot fix a target', async ({ page }) => {
    await btn(page, '#panel-nonce', 'Try to fix a target under two nonces').click();

    const section = page.locator('#panel-nonce .wagner-fixed');
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

  test('the ROS attack forges at FULL width, with nothing reduced', async ({ page }) => {
    const errors = noPageErrors(page);
    await btn(page, '#panel-nonce', 'Forge at full 256-bit width').click();

    const section = page.locator('#panel-nonce .ros-section');
    await expect(section.locator('.verdict-alarm')).toContainText('Forged', { timeout: 60_000 });
    // The distinguishing claim versus Wagner: no reduced parameter anywhere.
    await expect(section).toContainText('256 bits');
    await expect(section).toContainText('none');
    // 256 sessions, 257 signatures — one more than were authorised.
    await expect(section).toContainText('257');
    // The linear relation must hold exactly.
    await expect(section.locator('.both-sides .verdict-pass')).toContainText('match exactly');
    await expect(section.locator('.msg-forged')).toHaveCount(1);
    expect(errors).toEqual([]);
  });

  test('ROS against two nonces loses its constant target and is rejected', async ({ page }) => {
    await btn(page, '#panel-nonce', 'Run ROS against two nonces').click();

    const section = page.locator('#panel-nonce .ros-fixed');
    await expect(section.locator('.verdict-pass', { hasText: 'Attack failed' })).toBeVisible();
    await expect(section.locator('.verdict-alarm')).toHaveCount(0);
    // Both comparisons must show a mismatch: the target moved, so the relation broke.
    await expect(section.locator('.both-sides .verdict-fail')).toHaveCount(2);
    await expect(section).toContainText('constant right-hand side');
  });

  test('is honest about what it does not cover', async ({ page }) => {
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

  test('three cases are pulled to the front, and they are the ones claimed', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-vectors').click();
    const featured = page.locator('#kat-featured');
    // Looked up by group + index in the source, so a vector-file reword shows here
    // as a missing case rather than silently dropping one.
    await expect(featured.locator('.kat-feature')).toHaveCount(3);
    await expect(featured).not.toContainText('was not found in the vector run');
    await expect(featured.locator('.pill-bad')).toHaveCount(0);
    // Two rejections that must name the signer, and one that must NOT reject at all.
    await expect(featured).toContainText('invalid_contribution(signer=1, contrib=pubkey)');
    await expect(featured).toContainText('invalid_contribution(signer=1, contrib=psig)');
    await expect(featured.locator('.kat-feature').nth(2)).toContainText('MUST ACCEPT');
    // It sits above the full catalogue rather than replacing it.
    await expect(page.locator('#panel-vectors .kat-item')).toHaveCount(56);
  });
});

test.describe('the byte-display switch', () => {
  test('hex is abbreviated by default and one control expands all of it', async ({ page }) => {
    const errors = noPageErrors(page);
    await page.goto('.');
    await btn(page, '#panel-session', 'Show all steps').click();

    const abbreviated = page.getByRole('button', { name: 'Abbreviated' });
    const full = page.getByRole('button', { name: 'Full bytes' });
    await expect(abbreviated).toHaveAttribute('aria-pressed', 'true');
    await expect(full).toHaveAttribute('aria-pressed', 'false');

    const values = page.locator('[data-hex-full]');
    expect(await values.count()).toBeGreaterThan(20);

    // Abbreviated: every value is shorter than the bytes it stands for, and the full
    // value is still in the DOM — nothing is thrown away, only elided.
    const shortened = async () =>
      values.evaluateAll(
        (els) => els.filter((e) => e.textContent !== e.getAttribute('data-hex-full')).length,
      );
    expect(await shortened()).toBe(await values.count());

    await full.click();
    await expect(full).toHaveAttribute('aria-pressed', 'true');
    await expect(abbreviated).toHaveAttribute('aria-pressed', 'false');
    expect(await shortened()).toBe(0);

    await abbreviated.click();
    expect(await shortened()).toBe(await values.count());
    expect(errors).toEqual([]);
  });

  test('the choice survives a reload, and later panels honour it', async ({ page }) => {
    await page.goto('.');
    await page.getByRole('button', { name: 'Full bytes' }).click();
    await page.reload();
    await expect(page.getByRole('button', { name: 'Full bytes' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    // A panel first rendered *after* the switch must come up full, which is the part a
    // subscribe-on-render implementation gets wrong.
    await page.locator('#tab-rogue').click();
    await btn(page, '#panel-rogue', 'Run the rogue-key attack').click();
    await expect(page.locator('#panel-rogue .attack-broken .verdict-alarm')).toContainText('Forged');
    const values = page.locator('#panel-rogue [data-hex-full]');
    expect(await values.count()).toBeGreaterThan(0);
    expect(
      await values.evaluateAll(
        (els) => els.filter((e) => e.textContent !== e.getAttribute('data-hex-full')).length,
      ),
    ).toBe(0);
  });

  test('copy controls sit on the values a learner takes elsewhere', async ({ page }) => {
    await page.goto('.');
    await btn(page, '#panel-session', 'Show all steps').click();
    // The aggregate key and the finished signature — the two things you would paste
    // into another tool. Not on every intermediate value.
    const copies = page.locator('#panel-session .copy-btn');
    await expect(copies).toHaveCount(2);
    await expect(copies.first()).toHaveAccessibleName(/^Copy /);
  });

  test('copying an abbreviated value yields the whole value', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== 'flows-desktop', 'clipboard permissions are Chromium-only');
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('.');
    await btn(page, '#panel-session', 'Show all steps').click();

    // The whole point of the pairing: the page shows 25 characters, the clipboard
    // gets all 64. Copying what is on screen would be quietly useless.
    const field = page.locator('#panel-session .value-with-copy').first();
    const shown = (await field.locator('code').innerText()).trim();
    const full = await field.locator('code').getAttribute('data-hex-full');
    expect(shown).not.toBe(full);
    expect(shown).toContain('…');

    await field.getByRole('button').click();
    const clipped = await page.evaluate(() => navigator.clipboard.readText());
    expect(clipped).toBe(full);
    expect(clipped).toHaveLength(64);
  });
});

test.describe('the guided tour', () => {
  test('walks ten stops and drives the tabs across them', async ({ page }) => {
    const errors = noPageErrors(page);
    await page.goto('.');
    // The invitation is the dominant first action; the bar only appears once started.
    await expect(page.locator('#tour-invite')).toBeVisible();
    await expect(page.locator('#tour-bar')).toBeHidden();

    await btn(page, '#tour-invite', 'Start the guided tour').click();
    await expect(page.locator('#tour-bar')).toBeVisible();
    await expect(page.locator('#tour-invite')).toBeHidden();

    const seenTabs = new Set<string>();
    for (let i = 1; i <= 10; i++) {
      await expect(page.locator('.tour-label')).toContainText(`Step ${i} of 10`);
      seenTabs.add((await page.locator('.tab-btn[aria-selected="true"]').innerText()).trim());
      // Progress is visible, not just internal state.
      await expect(page.locator('.tour-dot-now')).toHaveCount(1);
      await expect(page.locator('.tour-dot-done')).toHaveCount(i - 1);
      if (i < 10) await page.locator('.tour-actions button', { hasText: 'Continue' }).click();
    }
    // The lesson genuinely crosses exhibits rather than staying in one tab — and
    // reaches every teaching exhibit, which is what leaves no gap in the lesson map.
    expect(seenTabs.has('Signing Session')).toBe(true);
    expect(seenTabs.has('Key Aggregation')).toBe(true);
    expect(seenTabs.has('Rogue Key Attack')).toBe(true);
    expect(seenTabs.has('Why Two Nonces')).toBe(true);
    // The evidence tab is the one exhibit the lesson deliberately never visits.
    expect(seenTabs.has('BIP-327 Vectors')).toBe(false);

    await page.locator('.tour-actions button', { hasText: 'Finish' }).click();
    await expect(page.locator('#tour-invite')).toBeVisible();
    expect(errors).toEqual([]);
  });

  test('survives a reload mid-lesson', async ({ page }) => {
    await page.goto('.');
    await btn(page, '#tour-invite', 'Start the guided tour').click();
    await page.locator('.tour-actions button', { hasText: 'Continue' }).click();
    await page.locator('.tour-actions button', { hasText: 'Continue' }).click();
    await expect(page.locator('.tour-label')).toContainText('Step 3 of 10');
    await page.reload();
    await expect(page.locator('.tour-label')).toContainText('Step 3 of 10');
  });

  test('the blind challenge exists when the tour jumps to it', async ({ page }) => {
    // Stop 9 anchors on a section that only renders once every step is revealed, so
    // the tour has to put the panel into that state itself.
    await page.goto('.');
    await btn(page, '#tour-invite', 'Start the guided tour').click();
    for (let i = 0; i < 8; i++) {
      await page.locator('.tour-actions button', { hasText: 'Continue' }).click();
    }
    await expect(page.locator('.tour-label')).toContainText('Back to the promise');
    await expect(page.locator('#tour-blind')).toBeVisible();
    await expect(page.locator('#tour-blind .sig-card')).toHaveCount(2);
  });

  test('Start over clears recorded predictions', async ({ page }) => {
    await page.goto('.');
    await page.locator('#panel-session .predict-opt').first().click();
    await expect(page.locator('#panel-session .predict-status')).toContainText('recorded');
    await btn(page, '#tour-invite', 'Start the guided tour').click();
    await page.locator('.tour-actions button', { hasText: 'Start over' }).click();
    await expect(page.locator('.tour-label')).toContainText('Step 1 of 10');
    await expect(page.locator('#panel-session .predict-status')).toBeEmpty();
  });
});

test.describe('predict before you compute', () => {
  test('a prediction is recorded but not graded until the experiment runs', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-rogue').click();
    const predict = page.locator('#panel-rogue .predict');
    await predict.locator('.predict-opt').first().click();
    // Recorded, and deliberately NOT told whether it was right.
    await expect(predict.locator('.predict-status')).toContainText('Prediction recorded');
    await expect(predict.locator('.pill-ok')).toHaveCount(0);
    await expect(predict.locator('.pill-bad')).toHaveCount(0);
    // The verdict arrives in the debrief, after the experiments.
    await expect(page.locator('#panel-rogue .predict-debrief .pill-ok')).toBeVisible();
  });

  test('the debrief nudges rather than spoils when nothing was predicted', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-nonce').click();
    const debrief = page.locator('#panel-nonce .predict-debrief').first();
    await expect(debrief).toContainText('did not record a prediction');
    await expect(debrief.locator('.pill')).toHaveCount(0);
  });

  test('the indistinguishability question is asked before the reveal', async ({ page }) => {
    await page.goto('.');
    // It must sit above the blind comparison in document order, not after it.
    const order = await page.evaluate(() => {
      const predict = document.querySelector('#tour-predict-indist');
      const steps = document.querySelector('#tour-steps');
      if (!predict || !steps) return 'missing';
      return predict.compareDocumentPosition(steps) & Node.DOCUMENT_POSITION_FOLLOWING
        ? 'before'
        : 'after';
    });
    expect(order).toBe('before');
  });
});

test.describe('the exit check', () => {
  test('rejects MuSig2-as-shown for a 2-of-3 requirement', async ({ page }) => {
    await page.goto('.');
    const transfer = page.locator('#tour-transfer');
    await expect(transfer).toBeVisible();
    const first = transfer.locator('.exit-q').first();
    await first.locator('.check-opt').first().click();
    await expect(first.locator('.pill-ok')).toBeVisible();
    await expect(first).toContainText('n-of-n');
    // And the wrong answer is corrected, not merely marked.
    await first.locator('.check-opt').nth(1).click();
    await expect(first.locator('.pill-bad')).toBeVisible();
    await expect(first).toContainText('FROST');
  });

  test('grades the threat-to-defence matching, including the no-defence row', async ({ page }) => {
    await page.goto('.');
    const task = page.locator('#tour-transfer .match-task');
    const selects = task.locator('select');
    await expect(selects).toHaveCount(4);
    // Answer all four correctly: rows are in the same order as the choice list.
    for (let i = 0; i < 4; i++) await selects.nth(i).selectOption({ index: i + 1 });
    await task.locator('button').click();
    await expect(task.locator('.pill-ok')).toContainText('All four matched');

    // Now get one wrong and check it is named.
    await selects.nth(2).selectOption({ index: 4 });
    await task.locator('button').click();
    await expect(task.locator('.pill-bad')).toBeVisible();
    await expect(task).toContainText('n-of-n signing simply fails');
  });
});

test.describe('the advanced material is optional', () => {
  test('Wagner and ROS are collapsed by default, behind a named disclosure', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-nonce').click();
    const advanced = page.locator('#tour-advanced');
    await expect(advanced).toContainText('Advanced: turn nonce control into a full forgery');
    expect(await advanced.evaluate((d: HTMLDetailsElement) => d.open)).toBe(false);
    // Both forgeries live inside it, so the core lesson ends at the nonce comparison.
    await expect(advanced.locator('.wagner-section')).toHaveCount(1);
    await expect(advanced.locator('.ros-section')).toHaveCount(1);
    // And it leads with the comparison table rather than dropping you into hex.
    await advanced.locator('summary').click();
    await expect(advanced.locator('table').first()).toContainText('Reduced parameter?');
  });
});

test.describe('jargon scaffolding', () => {
  test('each step shows the one term it needs, and it matches the glossary', async ({ page }) => {
    await page.goto('.');
    await btn(page, '#panel-session', 'Show all steps').click();

    const asides = page.locator('#panel-session .step-card .term-aside');
    await expect(asides).toHaveCount(6);
    const terms = await asides.locator('dt').allTextContents();
    // Each stage names the word it is the first to require, in dependency order.
    expect(terms.map((t) => t.replace('TERM', ''))).toEqual([
      'Secret key / public key',
      'Coefficient',
      'Nonce',
      'Challenge',
      'mod n',
      'Aggregate',
    ]);

    // The definitions are rendered from the same array the glossary uses, so a term
    // shown beside a stage must exist in it — this is the drift guard.
    const glossary = page.locator('#panel-session .glossary');
    expect(await glossary.evaluate((d: HTMLDetailsElement) => d.open)).toBe(false);
    await glossary.locator('summary').click();
    const defined = await glossary.locator('dt').allTextContents();
    for (const t of terms) expect(defined).toContain(t.replace('TERM', ''));
  });
});

test.describe('the tab strip is the lesson map', () => {
  test('marks exhibits the tour has finished, in words as well as colour', async ({ page }) => {
    await page.goto('.');
    // Outside the lesson there is no order to be ahead or behind of.
    await expect(page.locator('.tab-tick')).toHaveCount(0);

    await btn(page, '#tour-invite', 'Start the guided tour').click();
    await expect(page.locator('.tab-btn.tab-done')).toHaveCount(0);

    // Five Continues reach stop 6 (the nonce panel), by which point both rogue stops
    // are behind us and no session stop is.
    for (let i = 0; i < 5; i++) await btn(page, '#tour-bar', 'Continue').click();
    await expect(page.locator('#tab-rogue')).toHaveClass(/tab-done/);
    await expect(page.locator('#tab-session')).not.toHaveClass(/tab-done/);
    // Colour is never the only channel: the state is in the accessible name too.
    await expect(page.locator('#tab-rogue')).toHaveAccessibleName(/Rogue Key Attack.*done/);

    await btn(page, '#tour-bar', 'Exit tour').click();
    await expect(page.locator('.tab-tick')).toHaveCount(0);
  });

  test('the vectors tab is separated as evidence rather than a sixth chapter', async ({ page }) => {
    await page.goto('.');
    // A divider, not a reordering — the tablist still contains only tabs.
    await expect(page.locator('.tab-list > *')).toHaveCount(5);
    await expect(page.locator('.tab-list > :not([role="tab"])')).toHaveCount(0);
    const border = await page
      .locator('#tab-vectors')
      .evaluate((el) => getComputedStyle(el).borderLeftStyle);
    expect(border).toBe('solid');
    // And no tour stop lands there, which is what the divider is claiming.
    await btn(page, '#tour-invite', 'Start the guided tour').click();
    for (let i = 0; i < 9; i++) {
      await expect(page.locator('#tab-vectors')).toHaveAttribute('aria-selected', 'false');
      await btn(page, '#tour-bar', 'Continue').click();
    }
  });
});

test.describe('linking into the lesson', () => {
  test('#step-N opens the tour on that stop', async ({ page }) => {
    await page.goto('./#step-6');
    await expect(page.locator('#tour-bar')).toBeVisible();
    await expect(page.locator('.tour-label')).toContainText('Step 6 of 10');
    await expect(page.locator('.tour-label')).toContainText('See what a coefficient does');
    // It really navigated, not just relabelled: stop 6 lives in another exhibit.
    await expect(page.locator('#tab-keyagg')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#tour-keyagg-drawn')).toBeVisible();
  });

  test('an incoming step survives a stored lesson at a different stop', async ({ page }) => {
    // The tour rewrites the hash whenever it renders, and it renders while mounting —
    // so a resumed lesson would overwrite the requested step before anything read it.
    await page.goto('.');
    await btn(page, '#tour-invite', 'Start the guided tour').click();
    await btn(page, '#tour-bar', 'Continue').click();
    await expect(page.locator('.tour-label')).toContainText('Step 2 of 10');

    await page.goto('./#step-9');
    await expect(page.locator('.tour-label')).toContainText('Step 9 of 10');
    expect(page.url()).toContain('#step-9');
  });

  test('the address bar follows the lesson, without flooding the back button', async ({ page }) => {
    await page.goto('.');
    await btn(page, '#tour-invite', 'Start the guided tour').click();
    await expect(page).toHaveURL(/#step-1$/);
    const entries = await page.evaluate(() => history.length);
    for (let i = 0; i < 3; i++) await btn(page, '#tour-bar', 'Continue').click();
    await expect(page).toHaveURL(/#step-4$/);
    // replaceState, not four new history entries: Back still leaves the lab rather
    // than stepping backwards through the lesson one stop at a time.
    expect(await page.evaluate(() => history.length)).toBe(entries);
  });

  test('leaving the tour clears the step from the URL', async ({ page }) => {
    await page.goto('./#step-3');
    await expect(page).toHaveURL(/#step-3$/);
    await btn(page, '#tour-bar', 'Exit tour').click();
    expect(page.url()).not.toContain('#step-');
  });

  test('an exhibit deep link is left alone when the tour never runs', async ({ page }) => {
    await page.goto('./#rogue');
    await expect(page.locator('#tab-rogue')).toHaveAttribute('aria-selected', 'true');
    await page.locator('#tab-nonce').click();
    // Only the tour writes to the hash, and it is not running.
    expect(page.url()).toContain('#rogue');
  });

  test('an out-of-range step clamps to the last one', async ({ page }) => {
    await page.goto('./#step-999');
    await expect(page.locator('.tour-label')).toContainText('Step 10 of 10');
  });

  test('a nonsense hash falls back to the default exhibit', async ({ page }) => {
    const errors = noPageErrors(page);
    await page.goto('.');
    // A separate navigation, because a lesson resumed from sessionStorage would
    // legitimately show the bar and mask the fallback being tested.
    await page.evaluate(() => sessionStorage.clear());
    await page.goto('./#step-banana');
    await expect(page.locator('#tab-session')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#tour-bar')).toBeHidden();
    expect(errors).toEqual([]);
  });

  test('the tour offers the link rather than hiding it in the address bar', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== 'flows-desktop', 'clipboard permissions are Chromium-only');
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('./#step-5');
    // By accessible name, NOT by visible text: the button relabels itself to
    // "Copied", and a hasText locator would stop matching at exactly the moment the
    // assertion needs it — it silently waits for the label to revert and passes on
    // the pre-click text instead.
    const copy = page.getByRole('button', { name: 'Copy a link to this step' });
    await expect(copy).toBeVisible();
    await expect(copy).toHaveText('Link to this step');
    await copy.click();
    await expect(copy).toHaveText('Copied');
    expect(await page.evaluate(() => navigator.clipboard.readText())).toContain('#step-5');
    // And it goes back, so the control does not look permanently spent.
    await expect(copy).toHaveText('Link to this step', { timeout: 3000 });
  });
});

test.describe('degrading honestly', () => {
  test('a panel that cannot render says so instead of going blank', async ({ page }) => {
    // A real failure mode, not a synthetic one: this lab generates every key and
    // nonce with WebCrypto the moment a panel renders, and WebCrypto is absent on an
    // insecure origin. Break it and the exhibit must explain itself.
    await page.addInitScript(() => {
      Object.defineProperty(crypto, 'getRandomValues', {
        value: () => {
          throw new Error('getRandomValues is not available in this context');
        },
      });
    });
    await page.goto('.');
    const panel = page.locator('#panel-session');
    await expect(panel).toContainText('This exhibit could not run');
    await expect(panel.locator('.verdict-fail')).toContainText('getRandomValues');
    await expect(panel).toContainText('WebCrypto');
    // Blank is the failure this replaces.
    expect((await panel.innerText()).trim().length).toBeGreaterThan(50);

    // And the failure is contained: switching tabs still works, and each exhibit
    // reports for itself rather than taking the page down.
    await page.locator('#tab-vectors').click();
    await expect(page.locator('#panel-vectors')).toBeVisible();
  });

  test('the page states plainly that it needs JavaScript', async ({ page }) => {
    await page.goto('.');
    const text = await page.locator('noscript').innerText({ timeout: 2000 }).catch(() => '');
    const html = await page.locator('noscript').innerHTML();
    // innerText is empty for a non-rendered noscript, so assert on the markup.
    expect(html + text).toContain('needs JavaScript');
    expect(html + text).toContain('Nothing here is precomputed');
  });
});

test.describe('motion and announcements', () => {
  test('the tour announces each stop to a screen reader', async ({ page }) => {
    await page.goto('.');
    const live = page.locator('[role="status"][aria-live="polite"]').first();
    // Present before the tour starts, and empty — a live region inserted at the same
    // moment its text changes is not reliably announced.
    await expect(live).toHaveCount(1);
    await expect(live).toBeEmpty();

    await btn(page, '#tour-invite', 'Start the guided tour').click();
    await expect(live).toContainText('Step 1 of 10');
    await expect(live).toContainText('The promise');
    await btn(page, '#tour-bar', 'Continue').click();
    await expect(live).toContainText('Step 2 of 10');
    // It carries the instruction too, not just the position.
    await expect(live).toContainText('commit to one');

    await btn(page, '#tour-bar', 'Exit tour').click();
    await expect(live).toBeEmpty();
  });

  /**
   * Asserted on the first animation frame after the click, because that is the only
   * thing that actually differs. `@media (prefers-reduced-motion)` sets
   * `scroll-behavior: auto`, but a `behavior` argument to scrollIntoView overrides
   * the stylesheet — measured, all three engines animate right through the
   * preference unless the JS asks for it. A wall-clock budget does NOT discriminate:
   * this test passed against the unfixed code until it was rewritten this way.
   */
  const scrollSettlesInstantly = (page: Page): Promise<boolean> =>
    page.evaluate(async () => {
      const go = [...document.querySelectorAll('.tour-actions button')].find((b) =>
        (b.textContent ?? '').startsWith('Continue'),
      ) as HTMLButtonElement;
      go.click();
      const at = (): Promise<number> =>
        new Promise((res) => requestAnimationFrame(() => res(Math.round(window.scrollY))));
      const firstFrame = await at();
      for (let i = 0; i < 45; i++) await at(); // let any animation finish
      return firstFrame === (await at());
    });

  test('reduced motion means the jump is instant, not animated', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('.');
    await btn(page, '#tour-invite', 'Start the guided tour').click();
    // Two stops in, so the next Continue is the tour's biggest jump: a different tab,
    // far down the page.
    for (let i = 0; i < 2; i++) await btn(page, '#tour-bar', 'Continue').click();
    await page.waitForTimeout(400);
    expect(await scrollSettlesInstantly(page)).toBe(true);
  });

  test('without that preference the same jump is animated', async ({ page }) => {
    // The other half of the pair: proves the assertion above is measuring the
    // preference rather than something that was always true.
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.goto('.');
    await btn(page, '#tour-invite', 'Start the guided tour').click();
    for (let i = 0; i < 2; i++) await btn(page, '#tour-bar', 'Continue').click();
    await page.waitForTimeout(400);
    expect(await scrollSettlesInstantly(page)).toBe(false);
  });
});

test.describe('bridges between exhibits', () => {
  test('every teaching panel says what it established and what comes next', async ({ page }) => {
    await page.goto('.');
    await btn(page, '#panel-session', 'Show all steps').click();
    await expect(page.locator('#panel-session .bridge')).not.toHaveCount(0);
    for (const [tab, panel] of [
      ['#tab-keyagg', '#panel-keyagg'],
      ['#tab-rogue', '#panel-rogue'],
      ['#tab-nonce', '#panel-nonce'],
    ] as const) {
      await page.locator(tab).click();
      const bridge = page.locator(`${panel} .bridge`).first();
      await expect(bridge).toContainText('What this established');
      await expect(bridge).toContainText('What it makes you ask');
    }
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
