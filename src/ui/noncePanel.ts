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
        'What is not here: the step from nonce control to an actual forged signature. That takes a search across many concurrent signing sessions — Wagner’s generalised-birthday algorithm on k lists (Drijvers et al., "On the Security of Two-Round Multi-Signatures", IEEE S&P 2019), or the polynomial-time ROS attack of Benhamouda, Lepoint, Loss, Orrù and Raykova (2020), which needs roughly log₂ n ≈ 256 concurrent sessions. Neither is a browser-tab workload, and simulating one with fake numbers would teach less than saying plainly that it is out of scope.',
      ),
      h(
        'p',
        {},
        'The honest summary: single-nonce two-round Schnorr multisig is broken by those attacks, MuSig2’s second nonce is the fix, and the mechanism you can watch here is the exact capability the attacks depend on.',
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
