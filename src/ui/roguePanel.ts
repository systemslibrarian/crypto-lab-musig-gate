/**
 * Break-it-yourself #1: the rogue-key attack.
 *
 * Two buttons, one attack, two aggregation rules. Under the naive rule the learner
 * produces a signature that the genuine BIP-340 verifier ACCEPTS without any honest
 * signer taking part — the colour reads as ALARM, not success, because the system
 * has been defeated. Under BIP-327 the identical attack is rejected, and the
 * attacker's fixed-point search is shown failing round by round.
 */
import {
  bridge,
  clear,
  code,
  field,
  h,
  labLink,
  learnerCheck,
  note,
  panelIntro,
  prediction,
  predictionDebrief,
  scrollRegion,
  short,
  textControl,
  verdict,
} from './dom.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { G, bytesToHex, cbytes, mul, negate, randomScalar, utf8 } from '../musig/field.js';
import {
  type Bip327RogueResult,
  type RogueKeyResult,
  attemptBip327Rogue,
  naiveRogueAttack,
  tryRogueKey,
} from '../musig/rogue.js';

export function renderRoguePanel(root: HTMLElement): void {
  let honest = [randomScalar(), randomScalar()];
  let text = 'Pay the attacker the entire balance';

  const naiveOut = h('div', { class: 'output', role: 'status', 'aria-live': 'polite' });
  const safeOut = h('div', { class: 'output', role: 'status', 'aria-live': 'polite' });
  const manualOut = h('div', { class: 'output', role: 'status', 'aria-live': 'polite' });

  const msg = textControl({
    id: 'rogue-message',
    label: 'Message the attacker wants signed',
    value: text,
    rows: 2,
    help: 'The honest signers never agree to this. Under the broken rule, they do not have to.',
    onInput: (v) => {
      text = v;
    },
  });

  const rogueInput = textControl({
    id: 'rogue-key',
    label: 'Your own rogue public key (33-byte compressed hex)',
    value: '',
    help: 'Pre-filled by "Solve for the rogue key" below, or paste your own. Malformed keys are rejected — a rogue key still has to be a real curve point.',
  });

  const secretInput = textControl({
    id: 'rogue-secret',
    label: 'The discrete log you want the aggregate key to have (hex scalar)',
    value: '',
    help: 'The attacker picks this first, then works backwards to a key that produces it.',
  });

  root.append(
    panelIntro(
      'The attack that broke naive multisig',
      'Combining public keys sounds harmless. It is not — if you combine them by simple addition, a participant who chooses their key after seeing everyone else’s can pick a key that cancels the others out. The group key then belongs to that one person, who can sign anything, alone, and every verifier will accept.',
      'This is not a subtle break. It is one subtraction, the rogue key is a perfectly valid public key that no format check can reject, and it works the first time. Run it below against the real BIP-340 verifier, then run the identical attack against BIP-327 and watch the coefficients stop it.',
    ),
    h(
      'div',
      { class: 'controls' },
      msg.wrap,
      h(
        'div',
        { class: 'action-row' },
        h(
          'button',
          {
            type: 'button',
            class: 'btn btn-ghost',
            onclick: () => {
              honest = [randomScalar(), randomScalar()];
              clear(naiveOut);
              clear(safeOut);
              clear(manualOut);
            },
          },
          'New honest signers',
        ),
      ),
    ),

    h('div', { id: 'tour-rogue-predict' }),
    prediction(
      'rogue-rule',
      'Two honest signers publish P_1 and P_2. An attacker publishes its key last, after seeing theirs. Which aggregation rule can it manipulate into a key that it alone controls?',
      [
        { label: 'Q = P_1 + P_2 + P_attacker', correct: true },
        { label: 'Q = a_1·P_1 + a_2·P_2 + a_3·P_attacker', correct: false },
        { label: 'Both rules', correct: false },
        { label: 'Neither — the keys are validated', correct: false },
      ],
    ),

    h(
      'section',
      { class: 'attack-block attack-broken', id: 'tour-rogue-naive' },
      h('h3', {}, h('span', { class: 'pill pill-bad' }, 'BROKEN'), ' Naive aggregation: Q = ΣP_i'),
      h(
        'p',
        { class: 'help' },
        'Two honest signers publish their keys. The attacker goes last and publishes t·G − (P_1 + P_2) for a t it chose, then signs alone.',
      ),
      h(
        'div',
        { class: 'action-row' },
        h(
          'button',
          {
            type: 'button',
            class: 'btn btn-primary',
            onclick: () => showNaive(),
          },
          'Run the rogue-key attack',
        ),
      ),
      naiveOut,
    ),

    h(
      'section',
      { class: 'attack-block attack-fixed', id: 'tour-rogue-fixed' },
      h('h3', {}, h('span', { class: 'pill pill-ok' }, 'BIP-327'), ' Aggregation with coefficients: Q = Σ a_i·P_i'),
      h(
        'p',
        { class: 'help' },
        'The same attacker, the same target, the same honest keys — but now the attacker’s coefficient is a hash of the very key it is trying to solve for. Watch the fixed-point search miss.',
      ),
      h(
        'div',
        { class: 'action-row' },
        h(
          'button',
          { type: 'button', class: 'btn btn-primary', onclick: () => showBip327() },
          'Run the same attack against BIP-327',
        ),
      ),
      safeOut,
    ),

    h(
      'section',
      { class: 'attack-block' },
      h('h3', {}, 'Do the algebra yourself'),
      h(
        'p',
        { class: 'help' },
        'Pick your own target secret and rogue key and submit them to whichever aggregation rule you like. The verifier is the same one the honest exhibits use.',
      ),
      rogueInput.wrap,
      secretInput.wrap,
      h(
        'div',
        { class: 'action-row' },
        h(
          'button',
          { type: 'button', class: 'btn btn-ghost', onclick: () => solveForMe() },
          'Solve for the rogue key',
        ),
        h(
          'button',
          { type: 'button', class: 'btn btn-ghost preset-reject', onclick: () => submitManual('naive') },
          'Submit to naive aggregation',
        ),
        h(
          'button',
          { type: 'button', class: 'btn btn-ghost preset-accept', onclick: () => submitManual('bip327') },
          'Submit to BIP-327 aggregation',
        ),
      ),
      manualOut,
    ),

    predictionDebrief(
      'rogue-rule',
      'Only the plain sum is manipulable. Q = ΣP_i is linear in the keys, so the attacker sets P_attacker = t·G − (P_1 + P_2) and owns the total. Under BIP-327 its coefficient is a hash of the very key it is solving for, so the same move requires a hash fixed point. And note what is NOT the answer: the rogue key is a perfectly well-formed curve point, so no amount of validation catches it — the defence has to be algebraic.',
    ),

    learnerCheck(
      'The naive attack succeeded and the verifier said "valid". Whose fault is that?',
      [
        { label: 'The key-setup rule — the signature really is valid', correct: true },
        { label: 'The verifier, for not checking harder', correct: false },
        { label: 'The honest signers, for publishing their keys first', correct: false },
      ],
      'The signature is genuinely valid under the group key, so no verifier could reject it without breaking Schnorr. The flaw is upstream, in how the group key was formed. This is why a successful forgery here is coloured as an alarm rather than a success: the primitive did its job, and the protocol around it did not.',
    ),

    bridge(
      'Key setup can be attacked, and hash-derived coefficients are what close it. A well-formed public key is not a safe public key.',
      'Signing does not only aggregate keys — every signature also aggregates fresh nonces. Can those be steered the same way?',
    ),

    note(
      'caveat',
      'Not production crypto — a teaching demo. Real deployments avoid this by using BIP-327 aggregation (as shown) or, historically, by demanding a proof of knowledge for each key. Plain single-signer Schnorr internals live in ',
      labLink('crypto-lab-schnorr-forge', 'crypto-lab-schnorr-forge'),
      '; BLS, where aggregation works differently and has its own rogue-key story, is ',
      labLink('crypto-lab-pairing-gate', 'crypto-lab-pairing-gate'),
      '.',
    ),
  );

  function digest(): Uint8Array {
    return sha256(utf8(text));
  }

  function showNaive(): void {
    clear(naiveOut);
    const r = naiveRogueAttack(honest, digest());
    naiveOut.append(
      ...commonRows(r),
      verdict(
        r.verdict.valid ? 'alarm' : 'pass',
        r.verdict.valid
          ? 'the real BIP-340 verifier accepted a signature no honest signer contributed to'
          : `the forgery was rejected — ${r.verdict.reason}`,
        r.verdict.valid ? 'Forged' : 'Attack failed',
      ),
      h(
        'p',
        { class: 'help' },
        `The attacker knows the aggregate key’s discrete log: ${r.attackerOwnsAggregate ? 'yes' : 'no'}. Independent check with @noble/curves’ verifier: ${r.verdict.nobleValid ? 'also accepted' : 'also rejected'}.`,
      ),
      note(
        'danger',
        'Read the colour carefully: the verifier saying yes is the ALARM here, not the success. Every cryptographic check passed and the group still lost control of its own key.',
      ),
    );
  }

  function showBip327(): void {
    clear(safeOut);
    const r: Bip327RogueResult = attemptBip327Rogue(honest, digest());
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
          h('th', { scope: 'col' }, 'Candidate rogue key'),
          h('th', { scope: 'col' }, 'Coefficient it really gets'),
          h('th', { scope: 'col' }, 'Aggregate key it really produces'),
          h('th', { scope: 'col' }, 'Hit target?'),
        ),
      ),
      h(
        'tbody',
        {},
        ...r.rounds.map((round) =>
          h(
            'tr',
            {},
            h('td', {}, String(round.round)),
            h('td', {}, h('code', {}, short(round.candidate, 8))),
            h('td', {}, h('code', {}, short(hex32(round.actualCoeff), 8))),
            h('td', {}, h('code', {}, short(round.actualAggregateX, 8))),
            h(
              'td',
              {},
              h(
                'span',
                { class: `pill pill-${round.hitTarget ? 'bad' : 'ok'}` },
                h('span', { 'aria-hidden': 'true' }, round.hitTarget ? '⚠ ' : '✕ '),
                round.hitTarget ? 'HIT' : 'missed',
              ),
            ),
          ),
        ),
      ),
    );

    safeOut.append(
      field('The aggregate key the attacker was aiming at', r.targetKeyX),
      field('The aggregate key the group actually has', r.aggregateKeyX),
      scrollRegion('Fixed-point search rounds', table),
      ...commonRows(r),
      verdict(
        r.verdict.valid ? 'alarm' : 'pass',
        r.verdict.valid
          ? 'the forgery was accepted, which must not happen under BIP-327 aggregation'
          : 'the attacker never reached its target key, so the signature it made alone does not verify under the group’s actual aggregate key',
        r.verdict.valid ? 'Forged' : 'Attack failed',
      ),
      h(
        'p',
        { class: 'help' },
        `The attacker owns the aggregate key: ${r.attackerOwnsAggregate ? 'yes' : 'no'}. Verifier’s stated reason: ${r.verdict.reason}. Independent check with @noble/curves’ verifier: ${r.verdict.nobleValid ? 'accepted' : 'also rejected'}.`,
      ),
      note(
        'info',
        'Each round the attacker solves for the key its current coefficient guess demands, then discovers the key it just built hashes to a different coefficient. Converging would mean finding a preimage-style fixed point in SHA-256, which is why the search is not merely slow — it has no algebraic shortcut.',
      ),
    );
  }

  function solveForMe(): void {
    const t = randomScalar();
    const sumHonest = honest.reduce((acc, d) => acc.add(mul(G, d)), mul(G, 0n));
    const roguePoint = mul(G, t).add(negate(sumHonest));
    secretInput.input.value = t.toString(16).padStart(64, '0');
    rogueInput.input.value = bytesToHex(cbytes(roguePoint));
    clear(manualOut);
    manualOut.append(
      note(
        'info',
        'Filled in: ',
        code('P_rogue = t·G − ΣP_honest'),
        '. Submit it to each aggregation rule and compare.',
      ),
    );
  }

  function submitManual(mode: 'naive' | 'bip327'): void {
    clear(manualOut);
    let r: RogueKeyResult;
    try {
      const secret = BigInt(`0x${secretInput.input.value.trim() || '0'}`);
      if (secret <= 0n) throw new Error('give a non-zero target secret (or press "Solve for the rogue key")');
      r = tryRogueKey(honest, rogueInput.input.value.trim(), secret, digest(), mode);
    } catch (err) {
      manualOut.append(
        verdict(
          'fail',
          `rejected before any signing happened — ${(err as Error).message}`,
          'Malformed input',
        ),
        h(
          'p',
          { class: 'help' },
          'Fail-closed: a malformed key never reaches the aggregation step. Note that this is a parsing rejection, not a defence — a well-formed rogue key is accepted here and defeated by the coefficients instead.',
        ),
      );
      return;
    }
    manualOut.append(
      h('p', { class: 'help' }, `Aggregation rule: ${mode === 'naive' ? 'naive Q = ΣP_i' : 'BIP-327 Q = Σa_i·P_i'}`),
      ...commonRows(r),
      verdict(
        r.verdict.valid ? 'alarm' : 'pass',
        r.verdict.valid
          ? 'the verifier accepted a signature no honest signer contributed to'
          : `the verifier rejected it — ${r.verdict.reason}`,
        r.verdict.valid ? 'Forged' : 'Attack failed',
      ),
    );
  }

  function commonRows(r: RogueKeyResult): HTMLElement[] {
    return [
      ...r.honestPubkeys.map((pk, i) => field(`Honest signer ${i + 1} key`, pk)),
      field('Rogue key published last', r.roguePubkey),
      field('Resulting aggregate key', r.aggregateKeyX),
      field('Signature the attacker produced alone', r.forgedSignature, { sub: '64 bytes' }),
    ];
  }
}

function hex32(x: bigint): string {
  return x.toString(16).padStart(64, '0');
}
