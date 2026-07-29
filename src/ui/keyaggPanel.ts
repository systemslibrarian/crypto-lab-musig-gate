/**
 * Key aggregation on its own, with the coefficients in the foreground.
 *
 * The session panel shows aggregation as one step in a flow. This panel is where a
 * learner can poke at the coefficients directly: change the key list and watch L
 * change, reorder it and watch Q move, and check Σ a_i·P_i against Q byte for byte
 * instead of taking the equation on faith.
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
import {
  G,
  add,
  bytesToHex,
  cbytes,
  cpoint,
  hexToBytes,
  keySort,
  mul,
  randomScalar,
  xbytes,
} from '../musig/field.js';
import { type PlainPk, keyAggWithTrace } from '../musig/keyagg.js';
import { naiveKeyAgg } from '../musig/naive.js';

export function renderKeyAggPanel(root: HTMLElement): void {
  let keys: PlainPk[] = freshKeys(3);
  const output = h('div', { class: 'output', role: 'status', 'aria-live': 'polite' });

  const countLabel = h('span', { class: 'range-value' }, String(keys.length));
  const countInput = h('input', {
    id: 'keyagg-count',
    type: 'range',
    min: '1',
    max: '6',
    step: '1',
    value: String(keys.length),
  }) as HTMLInputElement;
  countInput.addEventListener('input', () => {
    keys = freshKeys(Number(countInput.value));
    countLabel.textContent = countInput.value;
    render();
  });

  root.append(
    panelIntro(
      'Why you cannot just add public keys',
      'Adding points on a curve is easy, so the obvious way to combine u public keys is Q = P_1 + P_2 + … + P_u. That is exactly what early multisig proposals did, and it is broken: whoever publishes their key last can subtract everyone else’s away and end up owning the group key alone.',
      'BIP-327 fixes it by weighting each key with a coefficient derived from a hash of the whole key list. Below, every coefficient is computed live, and the weighted sum is checked against the aggregate key byte for byte.',
    ),
    h(
      'div',
      { class: 'controls' },
      h(
        'div',
        { class: 'control' },
        h('label', { for: 'keyagg-count' }, 'Number of keys in the list'),
        h('div', { class: 'input-row' }, countInput, countLabel),
      ),
      h(
        'div',
        { class: 'action-row' },
        h(
          'button',
          { type: 'button', class: 'btn btn-primary', onclick: () => { keys = freshKeys(keys.length); render(); } },
          'New key set',
        ),
        h(
          'button',
          { type: 'button', class: 'btn btn-ghost', onclick: () => { keys = [...keys].reverse(); render(); } },
          'Reverse the order',
        ),
        h(
          'button',
          { type: 'button', class: 'btn btn-ghost', onclick: () => { keys = keySort(keys); render(); } },
          'Apply KeySort',
        ),
        h(
          'button',
          {
            type: 'button',
            class: 'btn btn-ghost',
            onclick: () => {
              const first = keys[0];
              keys = keys.map(() => first);
              render();
            },
          },
          'Make every key identical',
        ),
      ),
    ),
    output,
  );

  function render(): void {
    clear(output);
    let trace;
    try {
      trace = keyAggWithTrace(keys).trace;
    } catch (err) {
      output.append(verdict('fail', `aggregation failed — ${(err as Error).message}`, 'Error'));
      return;
    }

    // Recompute Σ a_i·P_i independently of keyAgg so the comparison below is a real
    // check and not the same value printed twice.
    let weighted = mul(G, 0n);
    for (const row of trace.rows) {
      weighted = add(weighted, mul(cpoint(hexToBytes(row.pubkey)), row.coeff));
    }
    const naive = naiveKeyAgg(keys);

    const table = h(
      'table',
      { class: 'kat-table' },
      h(
        'thead',
        {},
        h(
          'tr',
          {},
          h('th', { scope: 'col' }, '#'),
          h('th', { scope: 'col' }, 'Public key P_i'),
          h('th', { scope: 'col' }, 'Coefficient a_i'),
          h('th', { scope: 'col' }, 'Source'),
        ),
      ),
      h(
        'tbody',
        {},
        ...trace.rows.map((row) =>
          h(
            'tr',
            {},
            h('td', {}, String(row.index + 1)),
            h('td', {}, h('code', {}, short(row.pubkey, 10))),
            h('td', {}, h('code', {}, short(hex32(row.coeff), 10))),
            h(
              'td',
              {},
              row.isSecondKey
                ? h('span', { class: 'pill pill-neutral' }, 'second key → 1')
                : h('span', { class: 'pill pill-neutral' }, 'hash of L ‖ P_i'),
            ),
          ),
        ),
      ),
    );

    output.append(
      field('L — tagged-hash("KeyAgg list", P_1 ‖ … ‖ P_u)', trace.L, {
        sub: 'changes if any key changes, or if the order changes',
      }),
      field('Second key', trace.secondKey, {
        sub:
          trace.secondKey === '00'.repeat(33)
            ? 'all keys identical, so the sentinel applies and every coefficient is hash-derived'
            : 'the first key differing from P_1 — this one gets coefficient 1',
      }),
      scrollRegion('Key-aggregation coefficients', table),
      bothSides(
        'The definition, checked rather than asserted — Q is recomputed here from the coefficients above:',
        { label: 'Σ a_i·P_i (recomputed)', value: bytesToHex(xbytes(weighted)) },
        { label: 'Q from KeyAgg', value: trace.aggregateX },
      ),
      field('Q, compressed', trace.aggregateCompressed, {
        sub: `y is ${trace.qHasEvenY ? 'even' : 'odd'}`,
      }),
      h(
        'div',
        { class: 'compare-block' },
        h('h3', {}, 'Against the broken version'),
        field('Naive Q = Σ P_i (no coefficients)', bytesToHex(xbytes(naive)), {
          sub: 'this is the forgeable one',
        }),
        field('BIP-327 Q = Σ a_i·P_i', trace.aggregateX, { sub: 'this is the one that resists rogue keys' }),
        verdict(
          bytesToHex(xbytes(naive)) === trace.aggregateX ? 'alarm' : 'pass',
          bytesToHex(xbytes(naive)) === trace.aggregateX
            ? 'the two rules agreed, which should not happen for a hash-derived coefficient'
            : 'the two aggregation rules give completely different keys — the coefficients are doing real work',
          bytesToHex(xbytes(naive)) === trace.aggregateX ? 'Unexpected' : 'Different',
        ),
      ),
      note(
        'info',
        'Aggregation is order-dependent: ',
        code('Reverse the order'),
        ' changes Q entirely. That is why BIP-327 also defines KeySort — signers who hold an unordered set of keys sort it first so everyone derives the same Q.',
      ),
      disclosure(
        'Why does one key get coefficient 1?',
        h(
          'p',
          {},
          'It is an optimisation for the overwhelmingly common case of aggregating keys you already control, and it is safe: at most one signer ever gets the shortcut, so at least u−1 coefficients remain hash-bound to the whole list. That is enough to pin Q down, because an attacker steering Q would still have to satisfy a hash fixed point on its own coefficient.',
        ),
        h(
          'p',
          {},
          'The "second key" is the first entry that differs from the first entry. If every key in the list is identical there is no such entry, so the spec uses a 33-byte zero sentinel that no real key can equal — press ',
          code('Make every key identical'),
          ' and watch every coefficient become hash-derived.',
        ),
      ),
      learnerCheck(
        'An attacker sees your key P_1 and wants the group key to be a key they control. Under BIP-327, why can’t they just solve for their own key?',
        [
          { label: 'Their coefficient depends on a hash of their own key', correct: true },
          { label: 'Their key would be rejected as invalid', correct: false },
          { label: 'The protocol requires a signature over the key list', correct: false },
        ],
        'Their coefficient is a hash of L ‖ P_rogue, and L hashes P_rogue too — so the key they need depends on the coefficient, which depends on the key. It is a hash fixed point, not an algebra problem. Their key would NOT be rejected: a rogue key is a perfectly valid curve point, which is precisely why the defence has to be algebraic rather than a validity check. Try it in the Rogue Key exhibit.',
      ),
      note(
        'caveat',
        'This panel aggregates independently-generated keys. It does not generate them jointly — distributed key generation is ',
        labLink('crypto-lab-dkg-gate', 'crypto-lab-dkg-gate'),
        '. Tweaking the aggregate key into a Taproot output key is implemented in this repo for spec-vector coverage but is not an exhibit here; see ',
        labLink('crypto-lab-bitcoin-script', 'crypto-lab-bitcoin-script'),
        '.',
      ),
    );
  }

  render();
}

function freshKeys(count: number): PlainPk[] {
  return Array.from({ length: count }, () => cbytes(mul(G, randomScalar())));
}

function hex32(x: bigint): string {
  return x.toString(16).padStart(64, '0');
}
