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
  bridge,
  clear,
  code,
  disclosure,
  field,
  h,
  hexValue,
  labLink,
  learnerCheck,
  note,
  panelIntro,
  prediction,
  predictionDebrief,
  scrollRegion,
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
import { attemptRosTwoNonce, forgeRos } from '../musig/ros.js';

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

  const rosOut = h('div', { class: 'output', role: 'status', 'aria-live': 'polite' });
  const rosTwoOut = h('div', { class: 'output', role: 'status', 'aria-live': 'polite' });
  const rosStatus = h('span', { class: 'step-progress' });
  const rosBtn = h(
    'button',
    { type: 'button', class: 'btn btn-primary', onclick: () => runRos() },
    'Forge at full 256-bit width',
  ) as HTMLButtonElement;
  const rosTwoBtn = h(
    'button',
    { type: 'button', class: 'btn btn-primary', onclick: () => runRosTwo() },
    'Run ROS against two nonces',
  ) as HTMLButtonElement;

  /** The advanced forgeries live inside a disclosure, appended after the shell. */
  const advancedHost = h('div', { class: 'advanced-sections' });

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

    h('div', { id: 'tour-nonce-predict' }),
    prediction(
      'nonce-steer',
      'The attacker publishes its nonce last, after seeing everyone else\u2019s. Can it choose a contribution that makes the plain sum R = ΣR_i land on a point it picked in advance?',
      [
        { label: 'Yes — one subtraction, first try, every time', correct: true },
        { label: 'Only with a long search', correct: false },
        { label: 'No — the sum is unpredictable', correct: false },
      ],
    ),

    h(
      'section',
      { class: 'attack-block attack-broken', id: 'tour-nonce-steer' },
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
      { class: 'attack-block attack-fixed grind-fixed', id: 'tour-nonce-fixed' },
      h('h3', {}, h('span', { class: 'pill pill-ok' }, 'BIP-327'), ' Two nonces each: R = R_1 + b·R_2'),
      h(
        'p',
        { class: 'help' },
        'Same attacker, same target. Each round it solves for the nonce its current b demands, then finds out what b the protocol really derives from the bytes it just published.',
      ),
      prediction(
        'nonce-b',
        'Now the multiplier b is computed from the aggregate nonce bytes — including the attacker\u2019s own. What happens when the attacker changes its nonce to steer the result?',
        [
          { label: 'b changes too, so the target moves', correct: true },
          { label: 'b stays fixed; only R moves', correct: false },
          { label: 'b is secret, so the attacker cannot compute it', correct: false },
        ],
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

    predictionDebrief(
      'nonce-steer',
      'One subtraction is all it takes: R_attacker = R_target − ΣR_honest. There is no search because a plain sum is reversible, and whoever moves last simply solves for their own term.',
    ),
    predictionDebrief(
      'nonce-b',
      'b is neither secret nor random — anyone can compute it. The problem is ordering: b = H(aggnonce ‖ Q ‖ m) and the aggnonce contains the attacker\u2019s own nonce, so choosing a nonce to hit a target needs a b that only exists once the nonce is chosen. That circularity is the entire second defence.',
    ),

    bridge(
      'A single nonce hands the challenge to whoever publishes last; a second nonce with a hash-derived coefficient takes it back.',
      'Controlling the nonce is a capability — how does an attacker turn it into an actual forged signature, and does that route also close?',
    ),

    h(
      'details',
      { class: 'disclose advanced-block', id: 'tour-advanced' },
      h('summary', {}, 'Advanced: turn nonce control into a full forgery'),
      h(
        'div',
        { class: 'disclose-body' },
        h(
          'p',
          {},
          'Everything above is enough to understand why MuSig2 commits two nonces. What follows is the research-grade evidence that nonce control really does become a forgery — two independent routes, both run for real, both failing once the second nonce is in place. It is optional.',
        ),
        scrollRegion(
          'The two forgery routes compared',
          h(
            'table',
            { class: 'kat-table' },
            h(
              'thead',
              {},
              h(
                'tr',
                {},
                h('th', { scope: 'col' }, 'Attack'),
                h('th', { scope: 'col' }, 'Concurrent sessions'),
                h('th', { scope: 'col' }, 'Reduced parameter?'),
                h('th', { scope: 'col' }, 'What it needs'),
                h('th', { scope: 'col' }, 'Why two nonces stop it'),
              ),
            ),
            h(
              'tbody',
              {},
              h(
                'tr',
                {},
                h('th', { scope: 'row' }, 'Wagner'),
                h('td', {}, '4'),
                h('td', {}, 'Challenge width only'),
                h('td', {}, 'A fixed k-list target'),
                h('td', {}, 'b makes the target depend on the candidate nonces'),
              ),
              h(
                'tr',
                {},
                h('th', { scope: 'row' }, 'ROS'),
                h('td', {}, '256'),
                h('td', {}, 'None'),
                h('td', {}, 'A constant right-hand side'),
                h('td', {}, 'b makes the right-hand side move'),
              ),
            ),
          ),
        ),
        advancedHost,
      ),
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
        'What is not reduced at all: the polynomial-time ROS attack of Benhamouda, Lepoint, Loss, Orrù and Raykova (2020), further down this page. It breaks the same schemes at the full 256-bit challenge width with no birthday search, at the cost of roughly 256 concurrent sessions. The Wagner route (Drijvers et al., "On the Security of Two-Round Multi-Signatures", IEEE S&P 2019) comes first only because four sessions is something you can actually watch.',
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

  advancedHost.append(
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
      { class: 'attack-block attack-fixed wagner-fixed' },
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

    h(
      'section',
      { class: 'attack-block attack-broken ros-section' },
      h(
        'h3',
        {},
        h('span', { class: 'pill pill-bad' }, 'BROKEN'),
        ' The same break with nothing reduced at all',
      ),
      h(
        'p',
        { class: 'help' },
        'The forgery above had to truncate the challenge so a birthday search would finish. This one does not truncate anything. It is the polynomial-time ROS attack of Benhamouda, Lepoint, Loss, Orrù and Raykova (2020), and against a single-nonce scheme it is pure linear algebra: 256 concurrent sessions, two candidate challenges computed offline per session, and the bit pattern falls out of one modular subtraction. No search anywhere.',
      ),
      h(
        'p',
        { class: 'help' },
        'Full 256-bit challenge, real secp256k1, real key-aggregation coefficients, a signing oracle that refuses to reuse a nonce, and the same verifier. 256 sessions in, 257 signatures out.',
      ),
      h('div', { class: 'action-row' }, rosBtn, rosStatus),
      rosOut,
    ),
    h(
      'section',
      { class: 'attack-block attack-fixed ros-fixed' },
      h(
        'h3',
        {},
        h('span', { class: 'pill pill-ok' }, 'BIP-327'),
        ' ROS against two nonces',
      ),
      h(
        'p',
        { class: 'help' },
        'The linear system is exactly as solvable. What it loses is a constant right-hand side — and a linear system whose target moves when you write down the solution is not a system you can solve.',
      ),
      h('div', { class: 'action-row' }, rosTwoBtn),
      rosTwoOut,
    ),
  );

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
            h(
              'td',
              { class: 'cell-moving' },
              a.b === null ? h('code', {}, 'n/a') : hexValue(hex32(a.b), { keep: 8 }),
            ),
            h('td', { class: 'cell-moving' }, hexValue(a.achievedX, { keep: 8 })),
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
      h(
        'ol',
        { class: 'loop-list' },
        h('li', {}, 'The attacker uses the b it currently believes.'),
        h('li', {}, 'It chooses nonce bytes intended to make R land on the target.'),
        h('li', {}, 'The protocol hashes the bytes it just published and derives a different b.'),
        h('li', {}, 'R is recomputed with that b — and misses.'),
      ),
      h(
        'p',
        { class: 'help' },
        'Every row of the table above is one turn of that loop. The b column is the thing that moved, and the aggregate-nonce column is the consequence.',
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
                    h('td', {}, hexValue(d.honestNonceX, { keep: 8 })),
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
                h('td', {}, hexValue(p.bs[0].toString(16), { keep: 8 })),
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

  function runRos(): void {
    clear(rosOut);
    rosBtn.disabled = true;
    rosStatus.textContent = 'opening 256 sessions…';
    setTimeout(() => {
      const started = performance.now();
      try {
        const r = forgeRos();
        const elapsed = Math.round(performance.now() - started);
        rosOut.append(
          h(
            'div',
            { class: 'wagner-stats' },
            stat('Challenge width', `${r.challengeBits} bits`),
            stat('Reduced parameters', 'none'),
            stat('Concurrent sessions', String(r.sessions)),
            stat('Signatures obtained', String(r.signaturesObtained)),
            stat('Scalar mults', String(r.scalarMultiplications)),
            stat('Time', `${elapsed} ms`),
          ),
          h(
            'p',
            { class: 'help' },
            `The honest signer authorised ${r.queriedMessageCount} routine payments and nothing else. It now also has a valid signature against it on:`,
          ),
          h(
            'ul',
            { class: 'msg-list', role: 'list' },
            h('li', { role: 'listitem', class: 'msg-forged' }, r.forgedMessage),
          ),
          scrollRegion(
            'A sample of the 256 sessions',
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
                  h('th', { scope: 'col' }, 'Honest nonce R_i'),
                  h('th', { scope: 'col' }, 'Bit of B'),
                  h('th', { scope: 'col' }, 'Offset α published'),
                ),
              ),
              h(
                'tbody',
                {},
                ...r.sampleSessions.map((d) =>
                  h(
                    'tr',
                    {},
                    h('th', { scope: 'row' }, String(d.index + 1)),
                    h('td', {}, hexValue(d.honestNonceX, { keep: 8 })),
                    h('td', {}, h('code', {}, String(d.bit))),
                    h('td', {}, h('code', {}, String(d.alpha))),
                  ),
                ),
                h(
                  'tr',
                  {},
                  h('th', { scope: 'row' }, '…'),
                  h('td', { colspan: '3' }, `${r.sessions - r.sampleSessions.length} more sessions, ${r.onesInB} of the 256 bits set`),
                ),
              ),
            ),
          ),
          bothSides(
            'The linear relation the attack had to satisfy — solved, not searched for:',
            { label: 'Σ ρ_i·e_i', value: r.sumRhoE },
            { label: 'e* for the forged message', value: r.eStar },
          ),
          field('Aggregate key', r.aggregateKeyX),
          field('Forged signature R', r.forgedR),
          field('Forged signature s', r.forgedS),
          verdict(
            r.verified ? 'alarm' : 'pass',
            r.verified
              ? `a full-width verifier accepted a signature on a message nobody authorised — ${r.sessions} sessions in, ${r.signaturesObtained} signatures out`
              : 'the forgery was rejected',
            r.verified ? 'Forged' : 'Attack failed',
          ),
          note(
            'danger',
            'Nothing was weakened to make this work. Unlike the search above, this is what the attack costs in reality: a few hundred milliseconds and enough patience to keep 256 signing sessions open at once.',
          ),
        );
      } catch (err) {
        rosOut.append(verdict('fail', `the attack did not complete — ${(err as Error).message}`, 'Error'));
      } finally {
        rosBtn.disabled = false;
        rosStatus.textContent = '';
      }
    }, 0);
  }

  function runRosTwo(): void {
    clear(rosTwoOut);
    const r = attemptRosTwoNonce();
    rosTwoOut.append(
      h(
        'div',
        { class: 'wagner-stats' },
        stat('Sessions', String(r.sessions)),
        stat('Target moved', r.targetDrifted ? 'yes' : 'no'),
      ),
      bothSides(
        'The target the system was solved against, and the target that actually applies once the offsets are published:',
        { label: 'Targeted e*', value: r.targetedEStar },
        { label: 'Actual e*', value: r.actualEStar },
      ),
      bothSides(
        'And so the linear relation the forgery depends on no longer holds:',
        { label: 'Σ ρ_i·e_i', value: r.sumRhoE },
        { label: 'e* that the verifier will use', value: r.actualEStar },
      ),
      field('Resulting signature R', r.forgedR),
      field('Resulting signature s', r.forgedS),
      verdict(
        r.verified ? 'alarm' : 'pass',
        r.verified
          ? 'the forgery was accepted, which must not happen under the two-nonce construction'
          : 'the same verifier that accepted the full-width forgery rejects this one',
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
