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
  bridge,
  disclosure,
  exitQuestion,
  field,
  glossary,
  h,
  labLink,
  matchingTask,
  note,
  panelIntro,
  prediction,
  predictionDebrief,
  scrollRegion,
  short,
  textControl,
  verdict,
} from './dom.js';
import { registerTourAction } from './tour.js';
import {
  type SessionResult,
  type Signer,
  dropOneSigner,
  loneSignerComparison,
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
    glossary([
      {
        term: 'Signer',
        plain: 'One person or device holding one secret key. This lab writes u for how many there are.',
      },
      {
        term: 'Secret key / public key',
        plain: 'A secret number d, and the curve point P = d·G you can safely publish. Deriving d back from P is the problem nobody knows how to solve.',
        formal: 'Written d_i and P_i below.',
      },
      {
        term: 'Nonce',
        plain: 'A fresh random number used for exactly one signature. Not a password, not reusable — reusing one across two messages leaks the secret key outright.',
        formal: 'Written k for the secret and R = k·G for the public commitment.',
      },
      {
        term: 'Challenge',
        plain: 'A number derived by hashing the nonce, the key, and the message together. It is what ties a signature to one specific message.',
        formal: 'Written e.',
      },
      {
        term: 'Aggregate',
        plain: 'Combine several things into one of the same kind. Here: many public keys into one public key, many nonces into one nonce, many partial signatures into one signature.',
      },
      {
        term: 'Coefficient',
        plain: 'A multiplier applied to someone’s key before adding it in, so that no one can steer the total by choosing their key last.',
        formal: 'Written a_i for keys and b for nonces.',
      },
      {
        term: 'x-only',
        plain: 'A curve point has an x and a y. BIP-340 stores only x (32 bytes) and rebuilds y by convention, which is why the code keeps flipping signs to agree on which y was meant.',
      },
      {
        term: 'n-of-n',
        plain: 'Every listed signer must take part. Not a quorum: with three signers, three must sign, and losing one key loses the funds.',
      },
      {
        term: 'mod n',
        plain: 'Scalars wrap around at a fixed huge number n (the group order), the way clock arithmetic wraps at 12. Every "+" and "·" on secrets below is really "+ then wrap".',
      },
    ]),
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
      h('div', { class: 'action-row', id: 'tour-run' }, nextBtn, allBtn, resetBtn, rekeyBtn, progress),
    ),
    // Asked here, before the stepper output, so it is a genuine prediction rather
    // than a comprehension check on something already on screen.
    h('div', { id: 'tour-predict-indist' }),
    prediction(
      'indistinguishable',
      'Before you run anything: a verifier is handed the finished 64-byte signature and the 32-byte aggregate key, and nothing else. Can it tell how many people signed?',
      [
        { label: 'No — the output looks identical either way', correct: true },
        { label: 'Yes, from the signature length', correct: false },
        { label: 'Yes, from the aggregate key', correct: false },
        { label: 'Only if it knows the key list in advance', correct: false },
      ],
    ),
    h('div', { id: 'tour-steps' }),
    output,
    transferSection(),
  );

  // The blind challenge only exists once every step is revealed, so the tour has to
  // be able to get the panel there itself.
  registerTourAction('session:showAll', () => goto(STEPS.length));

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
      output.append(loneSignerSection(r));
      output.append(breakItSection(r));
      output.append(
        predictionDebrief(
          'indistinguishable',
          'The aggregate signature is 64 bytes and the aggregate key is 32 bytes for any number of signers, and both are ordinary BIP-340 values — so a 50/50 guess is the best anyone can do. That constant size and that privacy are the practical reasons MuSig2 exists. Note the flip side: the signer set is not recoverable from the chain either, so a group that needs an audit trail has to record it somewhere else.',
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
    // Each row names the OPERATION being performed, not just the values. "Many things
    // became one thing" is the easy half; "each was multiplied by a coefficient first,
    // and that coefficient is what makes it safe" is the half that matters.
    const rows: {
      label: string;
      parts: string[];
      partLabels: string[];
      agg: string | null;
      unit: string;
      op: string;
    }[] = [
      {
        label: 'Public keys',
        unit: '33 bytes each',
        op: atStep >= 2 ? 'each × a_i, then summed' : 'not yet combined',
        parts: r.signers.map((s) => short(s.pubkey, 6)),
        partLabels: r.signers.map((_, i) => (atStep >= 2 ? `a_${i + 1}·P_${i + 1}` : `P_${i + 1}`)),
        agg: atStep >= 2 ? short(r.aggregateKeyX, 6) : null,
      },
      {
        label: 'Nonces',
        unit: '2 per signer',
        op: atStep >= 4 ? 'halves summed, then R_1 + b·R_2' : 'not yet combined',
        parts:
          atStep >= 3
            ? r.round1.pubnonces.map((p) => `${short(p.first, 4)} · ${short(p.second, 4)}`)
            : [],
        partLabels: r.round1.pubnonces.map((_, i) => `R_${i + 1}1 · R_${i + 1}2`),
        agg: atStep >= 4 ? short(r.sessionValues.rx, 6) : null,
      },
      {
        label: 'Signatures',
        unit: '32-byte scalar each',
        op: atStep >= 6 ? 'added, mod n' : 'not yet combined',
        parts: atStep >= 5 ? r.round2.map((p) => short(p.psigHex, 6)) : [],
        partLabels: r.round2.map((_, i) => `s_${i + 1}`),
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
                  h(
                    'code',
                    { class: 'chip' },
                    h('span', { class: 'chip-idx' }, row.partLabels[i] ?? `${i + 1}`),
                    p,
                  ),
                )
              : [h('span', { class: 'collapse-pending' }, 'not computed yet')]),
          ),
          h(
            'div',
            { class: 'collapse-arrow' },
            h('span', { 'aria-hidden': 'true' }, '→'),
            h('span', { class: 'collapse-op' }, row.op),
          ),
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
          disclosure(
            'Show the secret keys (so you can check the arithmetic yourself)',
            h(
              'p',
              {},
              'Normally these never leave a signer. They are shown here because step 5’s equation s_i = k_i1 + b·k_i2 + e·a_i·d_i cannot be checked by hand without d_i — and being able to check it is the point of the exhibit.',
            ),
            ...r.signers.map((s, idx) => field(`${s.label} secret scalar d_${idx + 1}`, s.secretKey)),
            note(
              'caveat',
              'These are throwaway keys generated in this tab by WebCrypto. They are never persisted, never transmitted, and are replaced whenever you press ',
              code('New keys'),
              '. Never paste a real secret key into a web page — including this one.',
            ),
          ),
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
          bridge(
            'The coefficients are not cosmetic — they are the only thing standing between this key list and an attacker who picks their key last.',
            'What exactly does that attacker do, and what happens if the coefficients are not there?',
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
          h(
            'div',
            { class: 'dep-chain', role: 'group', 'aria-label': 'How the nonce coefficient is derived' },
            h('span', { class: 'dep-node' }, 'aggregate nonce bytes'),
            h('span', { class: 'dep-arrow', 'aria-hidden': 'true' }, '→'),
            h('span', { class: 'dep-node dep-node-key' }, 'b = H(aggnonce ‖ Q ‖ m)'),
            h('span', { class: 'dep-arrow', 'aria-hidden': 'true' }, '→'),
            h('span', { class: 'dep-node' }, 'R = R_1 + b·R_2'),
            h('span', { class: 'dep-arrow', 'aria-hidden': 'true' }, '→'),
            h('span', { class: 'dep-node' }, 'e = H(R ‖ Q ‖ m)'),
          ),
          h(
            'p',
            { class: 'help' },
            'Read that chain left to right and the second defence is obvious: a signer who changes its nonce changes the first box, which changes every box after it. There is no way to move R without moving b first.',
          ),
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
              field('s_i', p.psigHex, { sub: '= k_i1 + b·k_i2 + e·a_i·d_i mod n' }),
              bothSides(
                'The aggregator checks this signer in the group, not in the scalar field — s_i·G against (R_i1 + b·R_i2)^± + e·a_i·g′·P_i:',
                { label: 's_i·G', value: p.sides.lhs },
                { label: '(R_i1 + b·R_i2)^± + e·a_i·g′·P_i', value: p.sides.rhs },
              ),
              disclosure(
                'The terms behind this signer’s scalar',
                field('a_i (key coefficient)', hex32(p.trace.a)),
                field('d_i (secret scalar, after the Q-parity flip)', hex32(p.trace.d)),
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
    const state: 'pass' | 'fail' = r.verdict.valid ? 'pass' : 'fail';
    const sig = r.aggregation.signatureHex.length / 2;
    const key = r.aggregateKeyX.length / 2;
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
        h('li', { role: 'listitem' }, `Signers who took part: ${r.signers.length}`),
        h('li', { role: 'listitem' }, `Signature size: ${sig} bytes — the same as one signer’s`),
        h('li', { role: 'listitem' }, `Public key size: ${key} bytes — the same as one signer’s`),
        h(
          'li',
          { role: 'listitem' },
          `Independent check with @noble/curves’ own verifier: ${r.verdict.nobleValid ? 'also valid' : 'also rejected'}${r.verdict.disagreement ? ' — DISAGREEMENT, which must never happen' : ' (the two implementations agree)'}`,
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

  // ------------------------------------------------- the claim, as a challenge

  /**
   * "Indistinguishable from a lone signer's" is the lab's headline claim, so it is
   * put to the learner as a question before it is answered. One of the two cards
   * below was made by this group; the other by @noble/curves' ordinary
   * single-signer `schnorr.sign`. Which slot is which is a WebCrypto coin flip.
   */
  function loneSignerSection(r: SessionResult): HTMLElement {
    const cmp = loneSignerComparison(r);
    const reveal = h('div', { class: 'guess-out', role: 'status', 'aria-live': 'polite' });

    const cards = cmp.slots.map((slot, i) =>
      h(
        'div',
        { class: 'sig-card' },
        h('h4', {}, `Signature ${i === 0 ? 'A' : 'B'}`),
        field('Public key', slot.keyX, { sub: `${slot.keyBytes} bytes, x-only` }),
        field('Signature', slot.signatureHex, { sub: `${slot.signatureBytes} bytes` }),
        verdict(
          slot.valid ? 'pass' : 'fail',
          slot.valid
            ? `accepted by the plain BIP-340 verifier${slot.nobleValid ? ', and by @noble/curves’ own' : ''}`
            : 'rejected',
          slot.valid ? 'Valid' : 'Rejected',
        ),
      ),
    );

    const guess = (choice: 0 | 1): void => {
      const right = choice === cmp.groupSlot;
      clear(reveal);
      reveal.append(
        h(
          'span',
          { class: `pill pill-${right ? 'ok' : 'bad'}` },
          h('span', { 'aria-hidden': 'true' }, right ? '✓ ' : '✕ '),
          right ? 'Right — but only by luck' : 'Wrong',
        ),
        h(
          'p',
          { class: 'help' },
          `Signature ${cmp.groupSlot === 0 ? 'A' : 'B'} is the one ${cmp.signerCount} signers made together; the other came from one keypair and one call to an ordinary Schnorr library. There is nothing in the bytes to go on — a 50/50 guess is the best anyone can do, which is exactly the property MuSig2 is claiming.`,
        ),
      );
    };

    const table = h(
      'table',
      { class: 'kat-table' },
      h(
        'thead',
        {},
        h(
          'tr',
          {},
          h('th', { scope: 'col' }, 'Property'),
          h('th', { scope: 'col' }, `The ${cmp.signerCount}-signer group`),
          h('th', { scope: 'col' }, 'One lone signer'),
          h('th', { scope: 'col' }, 'Same?'),
        ),
      ),
      h(
        'tbody',
        {},
        ...cmp.comparedProperties.map((row) =>
          h(
            'tr',
            {},
            h('th', { scope: 'row' }, row.property),
            h('td', {}, row.group),
            h('td', {}, row.lone),
            h(
              'td',
              {},
              h(
                'span',
                { class: `pill pill-${row.same ? 'ok' : 'bad'}` },
                h('span', { 'aria-hidden': 'true' }, row.same ? '✓ ' : '✕ '),
                row.same ? 'identical' : 'differs',
              ),
            ),
          ),
        ),
      ),
    );

    return h(
      'div',
      { class: 'aha', id: 'tour-blind' },
      h('h3', {}, 'One of these was signed by a group. Which one?'),
      h(
        'p',
        { class: 'help' },
        `Both signatures below are over the same message. One is this session’s aggregate from ${cmp.signerCount} signers. The other was produced by @noble/curves’ ordinary single-signer Schnorr implementation, which has never heard of MuSig. Look at them, pick one, then reveal.`,
      ),
      h('div', { class: 'sig-pair' }, ...cards),
      h(
        'div',
        { class: 'preset-row', role: 'group', 'aria-label': 'Which signature did the group make?' },
        h(
          'button',
          { type: 'button', class: 'btn btn-ghost', onclick: () => guess(0) },
          'A was the group',
        ),
        h(
          'button',
          { type: 'button', class: 'btn btn-ghost', onclick: () => guess(1) },
          'B was the group',
        ),
      ),
      reveal,
      scrollRegion('Group signature compared with a lone signer’s', table),
      verdict(
        cmp.indistinguishable ? 'pass' : 'fail',
        cmp.indistinguishable
          ? 'every observable property matches — a verifier, and a blockchain, cannot tell the two apart'
          : 'some property differs, which would break the indistinguishability claim',
        cmp.indistinguishable ? 'Indistinguishable' : 'Distinguishable',
      ),
      note(
        'caveat',
        'This is indistinguishability of the SIGNATURE, not of the signers. Anyone who watched the two rounds of network traffic, or who already knows the group’s key list, learns the signer set immediately. MuSig2 hides the group from whoever reads the finished signature — not from a participant, and not from a network observer.',
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

  /**
   * The exit check. Not a recap — a scenario the learner has not seen, because the
   * question that matters is whether the idea transfers. The 2-of-3 case is the most
   * dangerous misconception this lab could leave behind: MuSig2 looks like "multisig"
   * and is not a quorum scheme.
   */
  function transferSection(): HTMLElement {
    return h(
      'section',
      { class: 'transfer', id: 'tour-transfer' },
      h('h2', {}, 'Exit check: can you use this?'),
      h(
        'p',
        { class: 'help' },
        'Two scenarios you have not seen on this page, and one matching exercise. If these come out right, you have the idea — not just the page.',
      ),
      exitQuestion(
        'A custody team wants any 2 of their 3 devices to be able to approve a payment, and they also want the on-chain spend to look like a single signer. Should they use the MuSig2 setup shown here?',
        [
          { label: 'No — this is 3-of-3; they need a threshold scheme', correct: true },
          { label: 'Yes — MuSig2 aggregates any subset', correct: false },
          { label: 'Yes, if they aggregate only the two devices that sign', correct: false },
        ],
        'No. MuSig2 is n-of-n: every key in the aggregated list must contribute, so a 3-key group needs all 3. It gives them key and signature aggregation, not a quorum — and if one device is lost, the funds are gone. FROST is the scheme for t-of-n, and it also produces one ordinary signature. Aggregating only the two devices that show up would produce a different aggregate key, which is not the key holding the funds.',
      ),
      exitQuestion(
        'A three-member group uses MuSig2 correctly. What can an observer learn from the key-path signature alone?',
        [
          { label: 'Nothing about the signers — it is an ordinary key and signature', correct: true },
          { label: 'The number of signers, from the signature size', correct: false },
          { label: 'The group members, from the aggregate key', correct: false },
        ],
        'From the signature alone: nothing. It is a 32-byte x-only key and a 64-byte signature, identical in form to a lone signer\u2019s. But be precise about the scope of that claim — a participant knows the key list, and anyone who watched the two rounds of network traffic saw the group assemble. MuSig2 hides the group from whoever reads the finished signature, not from everyone.',
      ),
      h('h3', {}, 'Match each threat to what actually defends against it'),
      matchingTask({
        idPrefix: 'transfer-match',
        rows: [
          {
            threat: 'A signer picks their public key last and cancels the honest keys',
            correct: 'Per-key coefficients bound to the full key list',
          },
          {
            threat: 'An attacker manipulates nonces across concurrent sessions',
            correct: 'Two nonces combined with a hash-derived b',
          },
          {
            threat: 'One of the n signers disappears',
            correct: 'Nothing in MuSig2 — n-of-n signing simply fails',
          },
          {
            threat: 'A signer reuses a secret nonce across two messages',
            correct: 'Operational nonce lifecycle — not solved by aggregation',
          },
        ],
        choices: [
          'Per-key coefficients bound to the full key list',
          'Two nonces combined with a hash-derived b',
          'Nothing in MuSig2 — n-of-n signing simply fails',
          'Operational nonce lifecycle — not solved by aggregation',
        ],
      }),
      note(
        'caveat',
        'The last two rows matter as much as the first two. Aggregation is not a substitute for availability or for nonce hygiene, and a demo that only showed the wins would be teaching you to over-trust it.',
      ),
    );
  }

  recompute();
  goto(1);
}

function hex32(x: bigint): string {
  return x.toString(16).padStart(64, '0');
}
