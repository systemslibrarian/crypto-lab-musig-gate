/**
 * Break-it-yourself #2: why there are two nonces.
 *
 * The learner picks a target aggregate nonce and attacks two schemes with the same
 * move. Against a single nonce per signer the target is hit exactly, first try, by
 * subtraction. Against BIP-327's two nonces the same move misses, because the
 * coefficient b is a hash of the very bytes the attacker just chose.
 *
 * The panel is explicit about the gap between "controls the nonce" and "forges a
 * signature": closing it takes Wagner's k-list algorithm or the polynomial-time ROS
 * attack, neither of which is run here.
 */
import {
  bothSides,
  clear,
  code,
  disclosure,
  field,
  h,
  labLink,
  learnerCheck,
  note,
  panelIntro,
  scrollRegion,
  short,
  verdict,
} from './dom.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { G, bytesToHex, cbytes, mul, randomScalar, utf8, xbytes } from '../musig/field.js';
import { keyAgg } from '../musig/keyagg.js';
import {
  type GrindResult,
  grindSingleNonce,
  grindTwoNonce,
  randomTargetNonce,
} from '../musig/noncecontrol.js';
import { attemptTwoNonceForgery, forgeSingleNonce } from '../musig/wagner.js';

const MSG = sha256(utf8('the message under attack'));

export function renderNoncePanel(root: HTMLElement): void {
  let target = randomTargetNonce();
  let honestCount = 2;

  const singleOut = h('div', { class: 'output', role: 'status', 'aria-live': 'polite' });
  const twoOut = h('div', { class: 'output', role: 'status', 'aria-live': 'polite' });
  const targetField = h('code', { class: 'field-value' }, bytesToHex(xbytes(target.point)));

  const countLabel = h('span', { class: 'range-value' }, String(honestCount));
  const countInput = h('input', {
    id: 'nonce-honest-count',
    type: 'range',
    min: '1',
    max: '4',
    step: '1',
    value: String(honestCount),
  }) as HTMLInputElement;
  countInput.addEventListener('input', () => {
    honestCount = Number(countInput.value);
    countLabel.textContent = countInput.value;
  });

  // --- the Wagner forgery controls -------------------------------------------
  let challengeBits = 27;
  const forgeOut = h('div', { class: 'output', role: 'status', 'aria-live': 'polite' });
  const twoOutWagner = h('div', { class: 'output', role: 'status', 'aria-live': 'polite' });
  const forgeStatus = h('span', { class: 'step-progress' });

  const widthSelect = h('select', { id: 'wagner-bits', class: 'mono-input wagner-select' }) as HTMLSelectElement;
  for (const bits of [21, 24, 27, 30]) {
    const opt = h('option', { value: String(bits) }, `${bits}-bit challenge`) as HTMLOptionElement;
    if (bits === challengeBits) opt.selected = true;
    widthSelect.append(opt);
  }
  widthSelect.addEventListener('change', () => {
    challengeBits = Number(widthSelect.value);
  });
  const widthSelectWrap = h(
    'span',
    { class: 'control-inline' },
    h('label', { for: 'wagner-bits' }, 'Search width'),
    widthSelect,
  );

  const forgeBtn = h(
    'button',
    { type: 'button', class: 'btn btn-primary', onclick: () => runForge() },
    'Forge a signature nobody authorised',
  ) as HTMLButtonElement;

  const twoBtn = h(
    'button',
    { type: 'button', class: 'btn btn-primary', onclick: () => runTwoNonceForge() },
    'Try to fix a target under two nonces',
  ) as HTMLButtonElement;

  root.append(
    panelIntro(
      'Why two nonces, and not one',
      'Every Schnorr signature needs a fresh random value — a nonce — and the group has to agree on one. The obvious approach is for each signer to publish one nonce and add them up. That works, right up until you notice that addition is reversible.',
      'Whoever publishes last can compute exactly the nonce that makes the total land on any value they choose. Since the signature’s challenge is a hash of that total, they get to choose the challenge — and a challenge you can choose is the starting point of a forgery.',
      'MuSig2’s answer is to have every signer commit two nonces and combine them as R = R_1 + b·R_2, where b is a hash of the aggregate nonce itself. Try to steer that and the target moves as you reach for it.',
    ),
    h(
      'div',
      { class: 'controls' },
      h(
        'div',
        { class: 'control' },
        h('span', { class: 'control-label' }, 'Target aggregate nonce the attacker wants'),
        targetField,
        h(
          'p',
          { class: 'help' },
          'Any point will do — what matters is that the attacker chose it in advance rather than the protocol producing it at random.',
        ),
      ),
      h(
        'div',
        { class: 'control' },
        h('label', { for: 'nonce-honest-count' }, 'Honest signers publishing before the attacker'),
        h('div', { class: 'input-row' }, countInput, countLabel),
      ),
      h(
        'div',
        { class: 'action-row' },
        h(
          'button',
          {
            type: 'button',
            class: 'btn btn-ghost',
            onclick: () => {
              target = randomTargetNonce();
              targetField.textContent = bytesToHex(xbytes(target.point));
              clear(singleOut);
              clear(twoOut);
            },
          },
          'New target nonce',
        ),
      ),
    ),

    h(
      'section',
      { class: 'attack-block attack-broken' },
      h('h3', {}, h('span', { class: 'pill pill-bad' }, 'BROKEN'), ' One nonce each: R = ΣR_i'),
      h(
        'p',
        { class: 'help' },
        'The attacker publishes R_att = R_target − ΣR_honest. One subtraction, no search.',
      ),
      h(
        'div',
        { class: 'action-row' },
        h(
          'button',
          { type: 'button', class: 'btn btn-primary', onclick: () => runSingle() },
          'Steer the aggregate nonce',
        ),
      ),
      singleOut,
    ),

    h(
      'section',
      { class: 'attack-block attack-fixed' },
      h('h3', {}, h('span', { class: 'pill pill-ok' }, 'BIP-327'), ' Two nonces each: R = R_1 + b·R_2'),
      h(
        'p',
        { class: 'help' },
        'Same attacker, same target. Each round it solves for the nonce its current b demands, then finds out what b the protocol really derives from the bytes it just published.',
      ),
      h(
        'div',
        { class: 'action-row' },
        h(
          'button',
          { type: 'button', class: 'btn btn-primary', onclick: () => runTwo() },
          'Try the same trick against two nonces',
        ),
      ),
      twoOut,
    ),

    h(
      'section',
      { class: 'attack-block attack-broken wagner-section' },
      h(
        'h3',
        {},
        h('span', { class: 'pill pill-bad' }, 'BROKEN'),
        ' Now actually forge a signature',
      ),
      h(
        'p',
        { class: 'help' },
        'Controlling the nonce is a capability, not yet a forgery. This closes the gap: four concurrent signing sessions against an honest signer, Wagner’s generalised-birthday algorithm over four lists, and out comes a valid signature on a message the honest signer never saw.',
      ),
      h(
        'p',
        { class: 'help' },
        'Everything is real secp256k1 — real keys, real point arithmetic, hash-derived key-aggregation coefficients so the key setup is not the flaw, a real signing oracle that never reuses a nonce, and a real verifier. Exactly one parameter is reduced: the challenge is truncated so the birthday search fits in a browser tab.',
      ),
      h('div', { class: 'action-row' }, forgeBtn, widthSelectWrap, forgeStatus),
      forgeOut,
    ),
    h(
      'section',
      { class: 'attack-block attack-fixed' },
      h(
        'h3',
        {},
        h('span', { class: 'pill pill-ok' }, 'BIP-327'),
        ' The same forgery attempt, against two nonces',
      ),
      h(
        'p',
        { class: 'help' },
        'Wagner’s k-tree needs to know what sum it is hunting for. With one nonce per signer that target is fixed before any grinding starts. With two, it is a function of the very nonces being searched over — so it moves. Each row below is the same attack aiming at a different target.',
      ),
      h('div', { class: 'action-row' }, twoBtn),
      twoOutWagner,
    ),

    disclosure(
      'What this shows, and what it does not',
      h(
        'p',
        {},
        'What is real above: controlling the aggregate nonce, and losing that control to b. Both are computed on live secp256k1 points, and the "hit" and "missed" verdicts are the actual arithmetic.',
      ),
      h(
        'p',
        {},
        'What is reduced: the forgery above truncates the challenge hash so Wagner’s search finishes in a browser tab. The algorithm is unmodified and the forged signature genuinely verifies in that reduced scheme. At the real 256-bit width the same k-tree with k = 4 needs on the order of 2^85 operations, so this is a devastating break in theory and not something you will ever watch happen. Nothing else is reduced: the curve, the keys, the coefficients, the oracle and the verifier are all real.',
      ),
      h(
        'p',
        {},
        'What is not here: the polynomial-time ROS attack of Benhamouda, Lepoint, Loss, Orrù and Raykova (2020), which breaks the same schemes without any birthday search but needs roughly 256 concurrent sessions. The Wagner route (Drijvers et al., "On the Security of Two-Round Multi-Signatures", IEEE S&P 2019) is the one implemented here because four sessions is something you can actually watch.',
      ),
      h(
        'p',
        {},
        'What is asserted rather than proven: that no cleverer attack exists against the two-nonce version. This page shows one specific attack failing for one specific, precise reason. The positive security claim comes from MuSig2’s proof, not from this demo.',
      ),
    ),

    learnerCheck(
      'Why can’t the attacker just solve for b as well, since it can see the formula?',
      [
        { label: 'b is a hash of the nonce the attacker is choosing', correct: true },
        { label: 'b is kept secret by the other signers', correct: false },
        { label: 'b is chosen at random by the verifier', correct: false },
      ],
      'b is not secret and not random — anyone can compute it. The problem is the ordering: b = H(aggnonce ‖ Q ‖ m), and the aggnonce contains the attacker’s own nonce. Choosing a nonce to hit a target requires knowing b, and knowing b requires having already chosen the nonce. That is a hash fixed point, which is exactly the kind of problem SHA-256 makes hard.',
    ),

    note(
      'caveat',
      'Not production crypto — a teaching demo. Separately from nonce aggregation: reusing a secret nonce across two messages leaks a Schnorr private key outright, which this lab prevents by zeroing each secret nonce on use. That attack is demonstrated end to end in ',
      labLink('crypto-lab-schnorr-forge', 'crypto-lab-schnorr-forge'),
      '.',
    ),
  );

  function aggregateKey() {
    const keys = Array.from({ length: honestCount + 1 }, () => cbytes(mul(G, randomScalar())));
    return keyAgg(keys).Q;
  }

  function runSingle(): void {
    clear(singleOut);
    const honest = Array.from({ length: honestCount }, () => randomScalar());
    const r = grindSingleNonce(honest, target.point);
    singleOut.append(
      ...resultRows(r),
      verdict(
        r.hitTarget ? 'alarm' : 'pass',
        r.hitTarget
          ? 'the attacker hit its chosen nonce EXACTLY, on the first attempt — and therefore chose the challenge'
          : 'the attacker missed its target',
        r.hitTarget ? 'Nonce hijacked' : 'Attack failed',
      ),
      h(
        'p',
        { class: 'help' },
        'There is no nonce coefficient in this scheme, so there is nothing to fight: the aggregate nonce is a plain sum and the last signer solves for it directly.',
      ),
      note(
        'danger',
        'Again, the attack SUCCEEDING is the alarm. Nothing failed to compute — the scheme worked exactly as designed, and that design is what hands the challenge to whoever publishes last.',
      ),
    );
  }

  function runTwo(): void {
    clear(twoOut);
    const honest: [bigint, bigint][] = Array.from({ length: honestCount }, () => [
      randomScalar(),
      randomScalar(),
    ]);
    const r = grindTwoNonce(honest, target.point, aggregateKey(), MSG);

    const table = h(
      'table',
      { class: 'kat-table' },
      h(
        'thead',
        {},
        h(
          'tr',
          {},
          h('th', { scope: 'col' }, 'Round'),
          h('th', { scope: 'col' }, 'b the protocol really derived'),
          h('th', { scope: 'col' }, 'Aggregate nonce it really produced'),
          h('th', { scope: 'col' }, 'Hit target?'),
        ),
      ),
      h(
        'tbody',
        {},
        ...r.attempts.map((a) =>
          h(
            'tr',
            {},
            h('td', {}, String(a.round)),
            h('td', {}, h('code', {}, a.b === null ? 'n/a' : short(hex32(a.b), 8))),
            h('td', {}, h('code', {}, short(a.achievedX, 8))),
            h(
              'td',
              {},
              h(
                'span',
                { class: `pill pill-${a.hitTarget ? 'bad' : 'ok'}` },
                h('span', { 'aria-hidden': 'true' }, a.hitTarget ? '⚠ ' : '✕ '),
                a.hitTarget ? 'HIT' : 'missed',
              ),
            ),
          ),
        ),
      ),
    );

    twoOut.append(
      ...resultRows(r),
      scrollRegion('Fixed-point search rounds', table),
      verdict(
        r.hitTarget ? 'alarm' : 'pass',
        r.hitTarget
          ? 'the attacker hit its target, which must not happen under the two-nonce construction'
          : 'every round missed — the target moves as the attacker reaches for it',
        r.hitTarget ? 'Nonce hijacked' : 'Attack failed',
      ),
      note(
        'info',
        'The attacker still publishes two perfectly well-formed nonces. Nothing rejected them; the arithmetic simply no longer lands where it wanted. Compare with the ',
        code('R = R_1 + b·R_2'),
        ' line in the signing session, where the same b is derived honestly.',
      ),
    );
  }

  /**
   * Run the real Wagner attack. `listBits` is scaled with the challenge width so the
   * search stays reliable: the k-tree wants lists of roughly 2^(bits/3), and a little
   * headroom on top makes an exact hit near-certain on the first attempt.
   */
  function runForge(): void {
    clear(forgeOut);
    forgeBtn.disabled = true;
    forgeStatus.textContent = 'searching…';
    // Yield once so the disabled state and status text actually paint before the
    // synchronous search blocks the main thread.
    setTimeout(() => {
      const started = performance.now();
      try {
        const listBits = Math.max(8, Math.ceil(challengeBits / 3) + 2);
        const r = forgeSingleNonce({ bits: challengeBits, listBits });
        const elapsed = Math.round(performance.now() - started);
        forgeOut.append(
          h(
            'div',
            { class: 'wagner-stats' },
            stat('Challenge width', `${r.bits} bits`),
            stat('Concurrent sessions', String(r.sessions)),
            stat('List size', r.listSize.toLocaleString()),
            stat('Point ops', r.listOps.toLocaleString()),
            stat('Search time', `${elapsed} ms`),
            stat('Attempts', String(r.attempts)),
          ),
          h('h4', {}, 'What the honest signer agreed to sign'),
          h(
            'ul',
            { class: 'msg-list', role: 'list' },
            ...r.queriedMessages.map((m) => h('li', { role: 'listitem' }, m)),
          ),
          h('h4', {}, 'What it now has a valid signature on'),
          h(
            'ul',
            { class: 'msg-list', role: 'list' },
            h('li', { role: 'listitem', class: 'msg-forged' }, r.forgedMessage),
          ),
          scrollRegion(
            'The four concurrent sessions',
            h(
              'table',
              { class: 'kat-table' },
              h(
                'thead',
                {},
                h(
                  'tr',
                  {},
                  h('th', { scope: 'col' }, 'Session'),
                  h('th', { scope: 'col' }, 'Honest nonce R_H'),
                  h('th', { scope: 'col' }, 'Adversary offset ρ'),
                  h('th', { scope: 'col' }, 'Challenge e_j'),
                ),
              ),
              h(
                'tbody',
                {},
                ...r.sessionDetail.map((d, i) =>
                  h(
                    'tr',
                    {},
                    h('th', { scope: 'row' }, String(i + 1)),
                    h('td', {}, h('code', {}, short(d.honestNonceX, 8))),
                    h('td', {}, h('code', {}, String(d.rho))),
                    h('td', {}, h('code', {}, String(d.e))),
                  ),
                ),
              ),
            ),
          ),
          bothSides(
            'The k-sum the search had to solve — and it had to hold over the integers, not just modulo 2^bits:',
            { label: 'Σ e_j from the four sessions', value: String(r.sumOfChallenges) },
            { label: 'e* for the forged message', value: String(r.eStar) },
          ),
          field('Aggregate key', r.aggregateKeyX),
          field('Forged signature R', r.forgedR),
          field('Forged signature s', r.forgedS),
          verdict(
            r.verified ? 'alarm' : 'pass',
            r.verified
              ? 'the verifier accepted a signature on a message the honest signer never saw — from four sessions, five signatures'
              : 'the forgery was rejected',
            r.verified ? 'Forged' : 'Attack failed',
          ),
          h(
            'p',
            { class: 'help' },
            `The honest signer never saw the forged message: ${r.honestSignerNeverSawIt ? 'confirmed' : 'FAILED — the demo is not showing what it claims'}. It also never reused a nonce, so this is not a nonce-reuse key leak; it is the k-sum.`,
          ),
          note('caveat', r.workAtFullWidth),
        );
      } catch (err) {
        forgeOut.append(
          verdict('fail', `the search did not converge — ${(err as Error).message}`, 'No solution'),
          h(
            'p',
            { class: 'help' },
            'Wagner’s k-tree is probabilistic. Pick a narrower search width and try again; the algorithm is unchanged, only the odds per attempt differ.',
          ),
        );
      } finally {
        forgeBtn.disabled = false;
        forgeStatus.textContent = '';
      }
    }, 0);
  }

  function runTwoNonceForge(): void {
    clear(twoOutWagner);
    const r = attemptTwoNonceForgery({ bits: challengeBits });
    twoOutWagner.append(
      scrollRegion(
        'Target drift across candidate nonce assignments',
        h(
          'table',
          { class: 'kat-table' },
          h(
            'thead',
            {},
            h(
              'tr',
              {},
              h('th', { scope: 'col' }, 'Adversary’s nonce choice'),
              h('th', { scope: 'col' }, 'First nonce coefficient b_1'),
              h('th', { scope: 'col' }, 'Resulting target e*'),
            ),
          ),
          h(
            'tbody',
            {},
            ...r.probes.map((p) =>
              h(
                'tr',
                {},
                h('th', { scope: 'row' }, p.label),
                h('td', {}, h('code', {}, short(p.bs[0].toString(16), 8))),
                h('td', {}, h('code', {}, String(p.eStar))),
              ),
            ),
          ),
        ),
      ),
      h(
        'div',
        { class: 'wagner-stats' },
        stat('Nonce assignments probed', String(r.probes.length)),
        stat('Distinct targets', String(r.distinctTargets)),
      ),
      verdict(
        r.targetDrifted ? 'pass' : 'alarm',
        r.targetDrifted
          ? 'every assignment produced a different target, so there is no fixed sum to search for — the k-tree’s precondition fails before it starts'
          : 'the target stayed fixed, which would make the k-tree applicable',
        r.targetDrifted ? 'No fixed target' : 'Target fixed',
      ),
      bothSides(
        'And if the adversary solves for the target it saw first, then publishes the nonces that solution needs:',
        { label: 'Target it solved against', value: String(r.targetedEStar) },
        { label: 'Target that actually applies', value: String(r.actualEStar) },
      ),
      field('Resulting signature R', r.forgedR),
      field('Resulting signature s', r.forgedS),
      verdict(
        r.verified ? 'alarm' : 'pass',
        r.verified
          ? 'the forgery was accepted, which must not happen under the two-nonce construction'
          : 'the same verifier that accepted the single-nonce forgery rejects this one',
        r.verified ? 'Forged' : 'Attack failed',
      ),
      h('p', { class: 'help' }, r.explanation),
    );
  }

  function stat(label: string, value: string): HTMLElement {
    return h(
      'div',
      { class: 'wagner-stat' },
      h('span', { class: 'wagner-stat-label' }, label),
      h('span', { class: 'wagner-stat-value' }, value),
    );
  }

  function resultRows(r: GrindResult): HTMLElement[] {
    return [
      ...r.honestNonces.map((n, i) => field(`Honest signer ${i + 1} nonce${r.scheme === 'two-nonce' ? 's' : ''}`, n)),
      ...r.attackerNonces.map((n, i) =>
        field(r.attackerNonces.length > 1 ? `Attacker nonce ${i + 1}` : 'Attacker nonce', n),
      ),
      field('Target aggregate nonce', r.targetX),
      field('Aggregate nonce actually produced', r.achievedX),
      r.b === null
        ? field('Nonce coefficient b', 'none — this scheme has no b', { mono: false })
        : field('Nonce coefficient b (final round)', hex32(r.b)),
    ];
  }
}

function hex32(x: bigint): string {
  return x.toString(16).padStart(64, '0');
}
