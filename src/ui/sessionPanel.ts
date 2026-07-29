/**
 * The headline exhibit: one real MuSig2 session, stepped.
 *
 * The mechanism this lab exists to teach is *collapse* — n keys become 1 key, n
 * nonce pairs become 1 nonce, n partial signatures become 1 signature — so the
 * panel shows that collapse happening, one stage at a time, with the real numbers
 * from a real session. The last step hands the result to a verifier that knows
 * nothing about MuSig and watches it accept.
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
  short,
  textControl,
  verdict,
} from './dom.js';
import {
  type SessionResult,
  type Signer,
  dropOneSigner,
  indistinguishability,
  makeSigners,
  runSession,
} from '../musig/session.js';

const STEPS = [
  {
    tag: 'STEP 1',
    title: 'Every signer has an ordinary key',
    lead: 'Nothing special yet — u independent secp256k1 keypairs. Secret keys stay in this tab and are never sent anywhere.',
  },
  {
    tag: 'STEP 2',
    title: 'The keys collapse into ONE key',
    lead: 'Each key gets a coefficient a_i derived from a hash of the entire key list, and Q = Σ a_i·P_i. This one aggregate key is what a chain or a verifier stores.',
  },
  {
    tag: 'STEP 3',
    title: 'Round 1 — every signer commits TWO nonces',
    lead: 'Two, not one. The second nonce is what stops a signer who publishes last from steering the group’s nonce.',
  },
  {
    tag: 'STEP 4',
    title: 'The nonces collapse into ONE nonce',
    lead: 'Each half is summed separately, then combined as R = R_1 + b·R_2 where b is a hash of the aggregate nonce itself.',
  },
  {
    tag: 'STEP 5',
    title: 'Round 2 — each signer answers the same challenge',
    lead: 'One scalar each: s_i = k_i1 + b·k_i2 + e·a_i·d_i. The aggregator checks each one on its own before combining them.',
  },
  {
    tag: 'STEP 6',
    title: 'The partial signatures collapse into ONE signature',
    lead: 'Add the scalars. That is the whole aggregation step — and the 64 bytes that come out are an ordinary BIP-340 signature.',
  },
];

export function renderSessionPanel(root: HTMLElement): void {
  let signers: Signer[] = makeSigners(3);
  let text = 'Move 2 BTC to the cold wallet';
  let sortKeys = true;
  let tamperIndex: number | null = null;
  let result: SessionResult | null = null;
  let error: string | null = null;
  let step = 1;

  const output = h('div', { class: 'output', role: 'status', 'aria-live': 'polite' });
  const countLabel = h('span', { class: 'range-value' }, String(signers.length));

  const countInput = h('input', {
    id: 'signer-count',
    type: 'range',
    min: '2',
    max: '5',
    step: '1',
    value: String(signers.length),
  }) as HTMLInputElement;
  countInput.addEventListener('input', () => {
    signers = makeSigners(Number(countInput.value));
    countLabel.textContent = countInput.value;
    tamperIndex = null;
    recompute();
    goto(Math.max(step, 1));
  });

  const msg = textControl({
    id: 'session-message',
    label: 'Message the group is signing',
    value: text,
    rows: 2,
    help: 'Signed as its 32-byte SHA-256 digest, exactly as a real deployment signs a 32-byte sighash.',
    onInput: (v) => {
      text = v;
      tamperIndex = null;
      recompute();
      goto(Math.max(step, 1));
    },
  });

  const sortToggle = h('input', {
    id: 'sort-keys',
    type: 'checkbox',
    checked: sortKeys,
  }) as HTMLInputElement;
  sortToggle.addEventListener('change', () => {
    sortKeys = sortToggle.checked;
    recompute();
    goto(Math.max(step, 1));
  });

  const nextBtn = h(
    'button',
    { type: 'button', class: 'btn btn-primary', onclick: () => goto(step + 1) },
    'Next step',
  ) as HTMLButtonElement;
  const allBtn = h(
    'button',
    { type: 'button', class: 'btn btn-ghost', onclick: () => goto(STEPS.length) },
    'Show all steps',
  );
  const resetBtn = h(
    'button',
    {
      type: 'button',
      class: 'btn btn-ghost',
      onclick: () => {
        tamperIndex = null;
        recompute();
        goto(1);
      },
    },
    'Restart at step 1',
  );
  const rekeyBtn = h(
    'button',
    {
      type: 'button',
      class: 'btn btn-ghost',
      onclick: () => {
        signers = makeSigners(signers.length);
        tamperIndex = null;
        recompute();
        goto(STEPS.length);
      },
    },
    'New keys',
  );
  const progress = h('span', { class: 'step-progress' });

  root.append(
    panelIntro(
      'Sign once, as a group',
      'Suppose three people jointly control a wallet and all three must approve every payment. The obvious way is to publish three keys and collect three signatures — everyone can see how many of you there are, and the transaction costs three times as much to store and check.',
      'MuSig2 does something better. The three of you combine your public keys into a single public key, combine fresh random values into a single random value, and each contribute one number toward a single signature. What comes out is one signature under one key — the same size and shape as a signature from one person, and accepted by software that has never heard of multisig.',
      'This panel runs that protocol for real and steps through it. Nothing below is precomputed or illustrative: every number is produced by the code in this page.',
    ),
    h(
      'div',
      { class: 'controls' },
      h(
        'div',
        { class: 'control' },
        h('label', { for: 'signer-count' }, 'How many signers'),
        h(
          'div',
          { class: 'input-row' },
          countInput,
          countLabel,
          h('span', { class: 'help' }, 'signers — every one of them required'),
        ),
        h(
          'p',
          { class: 'help' },
          'MuSig2 is n-of-n: every listed signer must take part. A t-of-n quorum is a different scheme — see ',
          labLink('crypto-lab-frost-threshold', 'crypto-lab-frost-threshold'),
          '.',
        ),
      ),
      msg.wrap,
      h(
        'div',
        { class: 'control' },
        h('span', { class: 'control-label' }, 'Key ordering'),
        h(
          'label',
          { class: 'radio', for: 'sort-keys' },
          sortToggle,
          h('span', {}, 'Sort the key list (BIP-327 KeySort)'),
        ),
        h(
          'p',
          { class: 'help' },
          'Key aggregation is order-dependent. Sorting is how signers derive the same aggregate key from an unordered set — untick it and watch Q change.',
        ),
      ),
      h('div', { class: 'action-row' }, nextBtn, allBtn, resetBtn, rekeyBtn, progress),
    ),
    output,
  );

  /**
   * Run the protocol once and cache the trace. Stepping only reveals more of the
   * SAME session — recomputing on every click would swap the numbers out from under
   * the learner, which would teach the opposite of what the stepper is for.
   */
  function recompute(): void {
    try {
      result = runSession(signers, text, { sortKeys, tamperIndex });
      error = null;
    } catch (err) {
      result = null;
      error = (err as Error).message;
    }
  }

  function goto(toStep: number): void {
    step = Math.max(1, Math.min(toStep, STEPS.length));
    nextBtn.disabled = step >= STEPS.length;
    progress.textContent = `Step ${step} of ${STEPS.length}`;
    render();
  }

  function render(): void {
    clear(output);
    if (error !== null) {
      output.append(verdict('fail', `session could not run — ${error}`, 'Error'));
      return;
    }
    if (!result) return;
    const r = result;

    output.append(collapseDiagram(r, step));

    for (let i = 0; i < step; i++) output.append(stepCard(i, r));

    if (step >= STEPS.length) {
      output.append(verifySection(r));
      output.append(breakItSection(r));
      output.append(
        learnerCheck(
          'A verifier is handed the 64-byte signature and the 32-byte aggregate key. Can it tell how many people signed?',
          [
            { label: 'No — the output looks identical either way', correct: true },
            { label: 'Yes, from the signature length', correct: false },
            { label: 'Yes, from the aggregate key', correct: false },
          ],
          'No. The aggregate signature is 64 bytes and the aggregate key is 32 bytes for any number of signers, and both are ordinary BIP-340 values. That privacy and that constant size are the practical reasons MuSig2 exists — but note the flip side: the signer set is not recoverable from the chain, so a group that needs an audit trail has to record it elsewhere.',
        ),
      );
      output.append(scopeNotes());
    } else {
      output.append(
        note(
          'info',
          'Press ',
          code('Next step'),
          ' to walk the protocol one stage at a time, or ',
          code('Show all steps'),
          ' to jump straight to the finished signature.',
        ),
      );
    }
  }

  // ---------------------------------------------------------------- the visual

  /**
   * The mechanism, drawn: three rows of per-signer chips collapsing into one chip.
   * A row only shows its aggregate once the step that computes it has been reached,
   * so the collapse is something the learner drives rather than a static picture.
   */
  function collapseDiagram(r: SessionResult, atStep: number): HTMLElement {
    const rows: { label: string; parts: string[]; agg: string | null; unit: string }[] = [
      {
        label: 'Public keys',
        unit: '33 bytes each',
        parts: r.signers.map((s) => short(s.pubkey, 6)),
        agg: atStep >= 2 ? short(r.aggregateKeyX, 6) : null,
      },
      {
        label: 'Nonces',
        unit: '2 per signer',
        parts: atStep >= 3 ? r.round1.pubnonces.map((p) => `${short(p.first, 4)} · ${short(p.second, 4)}`) : [],
        agg: atStep >= 4 ? short(r.sessionValues.rx, 6) : null,
      },
      {
        label: 'Signatures',
        unit: '32-byte scalar each',
        parts: atStep >= 5 ? r.round2.map((p) => short(p.psigHex, 6)) : [],
        agg: atStep >= 6 ? short(r.aggregation.signatureHex, 6) : null,
      },
    ];

    return h(
      'div',
      { class: 'collapse', role: 'group', 'aria-label': 'Aggregation diagram' },
      ...rows.map((row) =>
        h(
          'div',
          { class: 'collapse-row' },
          h(
            'div',
            { class: 'collapse-head' },
            h('span', { class: 'collapse-label' }, row.label),
            h('span', { class: 'collapse-unit' }, row.unit),
          ),
          h(
            'div',
            { class: 'collapse-parts' },
            ...(row.parts.length
              ? row.parts.map((p, i) =>
                  h('code', { class: 'chip' }, h('span', { class: 'chip-idx' }, `${i + 1}`), p),
                )
              : [h('span', { class: 'collapse-pending' }, 'not computed yet')]),
          ),
          h('div', { class: 'collapse-arrow', 'aria-hidden': 'true' }, '→'),
          h(
            'div',
            { class: 'collapse-agg' },
            row.agg
              ? h('code', { class: 'chip chip-agg reveal' }, h('span', { class: 'chip-idx' }, '1'), row.agg)
              : h('span', { class: 'collapse-pending' }, '—'),
          ),
        ),
      ),
    );
  }

  // ---------------------------------------------------------------- step cards

  function stepCard(i: number, r: SessionResult): HTMLElement {
    const meta = STEPS[i];
    const body = h('div', { class: 'step-body' });
    switch (i) {
      case 0:
        body.append(
          ...r.signers.map((s, idx) =>
            field(`${s.label} public key`, s.pubkey, { sub: `P_${idx + 1}, compressed` }),
          ),
          field('Message digest actually signed', r.messageDigest, { sub: 'SHA-256 of the text above' }),
        );
        break;
      case 1: {
        body.append(
          field('L — the commitment to the whole key list', r.keyAgg.L, {
            sub: 'tagged-hash("KeyAgg list", P_1 ‖ … ‖ P_u)',
          }),
          field('Second key (gets coefficient 1)', r.keyAgg.secondKey, {
            sub: 'the first key differing from P_1',
          }),
          ...r.keyAgg.rows.map((row) =>
            h(
              'div',
              { class: 'coeff-row' },
              h(
                'div',
                { class: 'coeff-head' },
                h('span', { class: 'coeff-name' }, `a_${row.index + 1}`),
                row.isSecondKey
                  ? h('span', { class: 'pill pill-neutral' }, 'second-key shortcut → 1')
                  : h('span', { class: 'pill pill-neutral' }, 'hash-derived'),
              ),
              field(`Coefficient a_${row.index + 1}`, hex32(row.coeff)),
              field(`a_${row.index + 1}·P_${row.index + 1}`, row.contribution, { sub: 'x-only' }),
            ),
          ),
          field('Q — the aggregate key', r.keyAgg.aggregateCompressed, {
            sub: `compressed; y is ${r.keyAgg.qHasEvenY ? 'even' : 'odd'}`,
          }),
          field('Q as it is published', r.aggregateKeyX, { sub: '32 bytes, x-only — this is the whole group' }),
          note(
            'info',
            'Every coefficient is a hash of ',
            code('L'),
            ' — which itself hashes every key, including its own. That circularity is exactly what defeats the rogue-key attack; the Rogue Key exhibit lets you try to break it.',
          ),
        );
        break;
      }
      case 2:
        body.append(
          ...r.round1.pubnonces.map((p) =>
            h(
              'div',
              { class: 'nonce-row' },
              h('span', { class: 'nonce-label' }, p.label),
              field('First nonce R_i1', p.first, { sub: 'x-only' }),
              field('Second nonce R_i2', p.second, { sub: 'x-only' }),
            ),
          ),
          note(
            'caveat',
            'A secret nonce must be used exactly once. The code enforces it: signing zeroes the secret nonce, so a second attempt fails loudly rather than leaking the key. Reuse across two messages is what hands a Schnorr private key to an attacker — see ',
            labLink('crypto-lab-schnorr-forge', 'crypto-lab-schnorr-forge'),
            '.',
          ),
        );
        break;
      case 3:
        body.append(
          field('R_1 = Σ R_i1', r.round1.agg.first.sum, {
            sub: r.round1.agg.first.isInfinity ? 'cancelled to infinity' : 'x-only',
          }),
          field('R_2 = Σ R_i2', r.round1.agg.second.sum, {
            sub: r.round1.agg.second.isInfinity ? 'cancelled to infinity' : 'x-only',
          }),
          field('Aggregate nonce on the wire', r.round1.agg.aggnonceHex, { sub: '66 bytes' }),
          field('b — the nonce coefficient', r.sessionValues.b, {
            sub: 'tagged-hash("MuSig/noncecoef", aggnonce ‖ Q ‖ m)',
          }),
          field('R = R_1 + b·R_2', r.sessionValues.rx, { sub: 'the nonce the signature commits to' }),
          field('e — the BIP-340 challenge', r.sessionValues.e, { sub: 'tagged-hash(R ‖ Q ‖ m)' }),
          ...(r.sessionValues.usedInfinityFallback
            ? [
                note(
                  'caveat',
                  'R_1 + b·R_2 landed on the point at infinity, so the spec’s defined fallback R = G applied. Rare, but real, and handled rather than crashed.',
                ),
              ]
            : []),
          note(
            'info',
            'b is a hash of the aggregate nonce, so it is not known until every signer has committed. That is the entire reason there are two nonces — the Why Two Nonces exhibit lets you attack both versions.',
          ),
        );
        break;
      case 4:
        body.append(
          ...r.round2.map((p) =>
            h(
              'div',
              { class: `partial-row ${p.verified ? 'partial-ok' : 'partial-bad'}` },
              h(
                'div',
                { class: 'partial-head' },
                h('span', { class: 'nonce-label' }, p.label),
                h(
                  'span',
                  { class: `pill pill-${p.verified ? 'ok' : 'bad'}` },
                  h('span', { 'aria-hidden': 'true' }, p.verified ? '✓ ' : '✕ '),
                  p.verified ? 'partial verified' : 'partial REJECTED',
                ),
              ),
              field('s_i', p.psigHex, { sub: 'k_i1 + b·k_i2 + e·a_i·d_i mod n' }),
              disclosure(
                'The terms behind this signer’s scalar',
                field('a_i (key coefficient)', hex32(p.trace.a)),
                field('k_i1 (first nonce, after the R-parity flip)', hex32(p.trace.k1Effective)),
                field('k_i2 (second nonce, after the R-parity flip)', hex32(p.trace.k2Effective)),
                h(
                  'p',
                  { class: 'help' },
                  `R has ${p.trace.rHasEvenY ? 'even' : 'odd'} y, so the nonces were ${p.trace.rHasEvenY ? 'used as-is' : 'negated'}; Q has ${r.keyAgg.qHasEvenY ? 'even' : 'odd'} y, so the secret key was ${r.keyAgg.qHasEvenY ? 'used as-is' : 'negated'}. That bookkeeping exists only because BIP-340 stores R and Q x-only.`,
                ),
              ),
            ),
          ),
          note(
            'info',
            'Each partial signature is verified on its own before anything is combined. That is what makes MuSig2 attributable: a bad signature is traced to a signer instead of leaving the group with an unexplained failure.',
          ),
        );
        break;
      case 5:
        body.append(
          ...r.aggregation.terms.map((t, idx) => field(`s_${idx + 1}`, t)),
          field('Σ s_i mod n', r.aggregation.sum),
          field('s in the finished signature', r.aggregation.s),
          bothSides(
            'Adding the partial scalars IS the aggregation step — no extra cryptography:',
            { label: 'Σ s_i mod n', value: r.aggregation.sum },
            { label: 's from the signature', value: r.aggregation.s },
          ),
          field('R.x ‖ s — the finished signature', r.aggregation.signatureHex, { sub: '64 bytes' }),
        );
        break;
      default:
        break;
    }

    return h(
      'div',
      { class: 'step-card reveal' },
      h('span', { class: 'trace-tag' }, meta.tag),
      h('h3', {}, meta.title),
      h('p', { class: 'step-lead' }, meta.lead),
      body,
    );
  }

  // ---------------------------------------------------------------- the "aha"

  function verifySection(r: SessionResult): HTMLElement {
    const info = indistinguishability(r);
    const state: 'pass' | 'fail' = r.verdict.valid ? 'pass' : 'fail';
    return h(
      'div',
      { class: 'aha' },
      h('h3', {}, 'Now hand it to a verifier that has never heard of MuSig'),
      h(
        'p',
        { class: 'help' },
        'The code below is a plain BIP-340 Schnorr verifier. It takes a 32-byte public key, a 64-byte signature and a message, and checks one equation. It has no notion of signers, coefficients, or rounds.',
      ),
      verdict(state, r.verdict.reason),
      h(
        'ul',
        { class: 'facts', role: 'list' },
        h('li', { role: 'listitem' }, `Signers who took part: ${info.signerCount}`),
        h('li', { role: 'listitem' }, `Signature size: ${info.signatureBytes} bytes — the same as one signer’s`),
        h('li', { role: 'listitem' }, `Public key size: ${info.aggregateKeyBytes} bytes — the same as one signer’s`),
        h(
          'li',
          { role: 'listitem' },
          `Independent check with @noble/curves’ own verifier: ${info.nobleValid ? 'also valid' : 'also rejected'}${info.agree ? ' (the two implementations agree)' : ' — DISAGREEMENT, which must never happen'}`,
        ),
      ),
      r.verdict.lhs && r.verdict.rhs
        ? bothSides(
            'The verifier computes both sides of s·G = R + e·Q and compares them:',
            { label: 's·G', value: r.verdict.lhs },
            { label: 'R + e·Q', value: r.verdict.rhs },
          )
        : null,
      disclosure(
        'The verifier’s stage-by-stage pipeline',
        h(
          'ul',
          { class: 'stage-list', role: 'list' },
          ...r.verdict.stages.map((s) =>
            h(
              'li',
              { class: `stage stage-${s.status}`, role: 'listitem' },
              h('span', { class: 'stage-icon', 'aria-hidden': 'true' }, s.status === 'pass' ? '✓' : '✕'),
              h('span', { class: 'stage-label' }, s.label),
              h('span', { class: 'stage-detail' }, s.detail),
            ),
          ),
        ),
      ),
    );
  }

  // ---------------------------------------------------------------- break it

  function breakItSection(r: SessionResult): HTMLElement {
    const outcome = h('div', { class: 'break-out', role: 'status', 'aria-live': 'polite' });

    const tamperBtns = r.round2.map((p, i) =>
      h(
        'button',
        {
          type: 'button',
          class: 'btn btn-ghost preset-reject',
          onclick: () => {
            tamperIndex = i;
            recompute();
            goto(STEPS.length);
          },
        },
        `Corrupt ${p.label}’s partial`,
      ),
    );

    const dropBtn = h(
      'button',
      {
        type: 'button',
        class: 'btn btn-ghost preset-reject',
        onclick: () => {
          const d = dropOneSigner(signers, text);
          clear(outcome);
          outcome.append(
            verdict('fail', d.error, 'Cannot sign'),
            h(
              'p',
              { class: 'help' },
              `${d.attempted} of ${d.required} signers contributed. MuSig2 is n-of-n; the quorum case IS `,
              labLink('crypto-lab-frost-threshold', 'crypto-lab-frost-threshold'),
              '.',
            ),
          );
        },
      },
      'Try signing with one signer missing',
    );

    if (tamperIndex != null) {
      const culprit = r.round2[tamperIndex];
      outcome.append(
        verdict(
          'fail',
          `the aggregate signature is invalid, and the aggregator can name the cause: ${culprit.label}`,
          'Rejected',
        ),
        h(
          'p',
          { class: 'help' },
          'One bit was flipped in one partial signature. The aggregate signature no longer satisfies s·G = R + e·Q, and the per-partial check above marks exactly which signer is responsible — nobody has to guess.',
        ),
      );
    }

    return h(
      'div',
      { class: 'break-it' },
      h('h3', {}, 'Break it yourself'),
      h(
        'p',
        { class: 'help' },
        'These buttons run against the same real code as everything above. Nothing is simulated, and nothing is a warning message standing in for a result.',
      ),
      h('div', { class: 'preset-row' }, ...tamperBtns, dropBtn),
      outcome,
    );
  }

  function scopeNotes(): HTMLElement {
    return disclosure(
      'What this lab is not',
      h(
        'ul',
        { class: 'facts', role: 'list' },
        h(
          'li',
          { role: 'listitem' },
          'Not a threshold scheme. MuSig2 is n-of-n; the quorum case IS ',
          labLink('crypto-lab-frost-threshold', 'crypto-lab-frost-threshold'),
          '.',
        ),
        h(
          'li',
          { role: 'listitem' },
          'Not an introduction to plain Schnorr. Keygen and single-signer signing internals are ',
          labLink('crypto-lab-schnorr-forge', 'crypto-lab-schnorr-forge'),
          ', which this lab builds on.',
        ),
        h(
          'li',
          { role: 'listitem' },
          'No distributed key generation. Each signer here generates its own key independently; DKG is ',
          labLink('crypto-lab-dkg-gate', 'crypto-lab-dkg-gate'),
          '.',
        ),
        h(
          'li',
          { role: 'listitem' },
          'Not BLS aggregation. That is a different primitive over pairing-friendly curves — ',
          labLink('crypto-lab-pairing-gate', 'crypto-lab-pairing-gate'),
          '.',
        ),
        h(
          'li',
          { role: 'listitem' },
          'No Taproot transaction assembly. Key tweaking is implemented for spec-vector coverage but not surfaced; spending paths are ',
          labLink('crypto-lab-bitcoin-script', 'crypto-lab-bitcoin-script'),
          '.',
        ),
      ),
      note(
        'caveat',
        'Not production crypto — a teaching demo. Real signers need constant-time arithmetic, nonce storage that guarantees single use, and an audited implementation such as libsecp256k1. A passing session here proves the arithmetic matches BIP-327 on these inputs; it proves nothing about side channels, key management, or the security of the deployment around it.',
      ),
    );
  }

  recompute();
  goto(1);
}

function hex32(x: bigint): string {
  return x.toString(16).padStart(64, '0');
}
