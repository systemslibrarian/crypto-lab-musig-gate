/**
 * The BIP-327 known-answer tests, executed in the browser on load.
 *
 * This table is not a report of a test run somewhere else — the runners in
 * ../musig/vectors.ts execute here, in this tab, against the same code the other
 * exhibits use. The same functions back the Vitest suite, so a green table and a
 * green CI run are the same claim.
 */
import { clear, code, disclosure, field, h, labLink, note, panelIntro, verdict } from './dom.js';
import { KAT_GROUPS, type KatResult, katSummary, runAllVectors } from '../musig/vectors.js';

/**
 * Three cases pulled to the front.
 *
 * Fifty-odd green rows are evidence but not a lesson — nobody reads fifty rows, and
 * the ones that matter most are invisible among the ones that are merely arithmetic.
 * These three are the cases that change how you would *write* an implementation:
 * one where rejecting is not enough because the report has to name a signer, one
 * where the obvious shortcut (reduce mod n) silently destroys a security property,
 * and one where the correct behaviour is to keep going through a value that has no
 * x-coordinate at all.
 *
 * Identified by group + index rather than by comment text so a vector-file update
 * that rewords a comment surfaces as a visible "case not found" rather than
 * silently dropping the featured case.
 */
interface Featured {
  group: string;
  index: number;
  title: string;
  why: (string | HTMLElement)[];
}

const FEATURED: Featured[] = [
  {
    group: 'key_agg',
    index: 4,
    title: 'A public key that is not a point on the curve',
    why: [
      'Rejecting is the easy half. BIP-327 requires the failure to be an ',
      code('invalid_contribution'),
      ' report that names which signer supplied the bad bytes — index 1 here — because an n-of-n group that merely aborts learns nothing and can be stalled forever by an anonymous saboteur. Attribution is what turns a failed signing round into an accusation.',
    ],
  },
  {
    group: 'sig_agg',
    index: 4,
    title: 'A partial signature at or above the group order',
    why: [
      'The tempting shortcut is to reduce the scalar mod n and carry on, because the arithmetic still works and the aggregate signature still verifies. BIP-327 says reject — and report signer 1, again by index. Accepting both ',
      code('s'),
      ' and ',
      code('s + n'),
      ' would mean a partial signature is no longer a unique encoding of what a signer sent, so the identifiable-abort property above quietly stops holding: a signer could disown the bytes it contributed. Being helpful about malformed input is how that gets lost.',
    ],
  },
  {
    group: 'nonce_agg',
    index: 1,
    title: 'A nonce half that cancels to the point at infinity',
    why: [
      'Here the correct answer is not to reject. Sum the second halves of every signer’s nonce and you can land on the identity, which has no x-coordinate to serialize — and any signer moving last can force exactly that, which is the same last-mover power the nonce exhibit is about. BIP-327 says serialize it as 33 zero bytes and continue; the signature that comes out is still valid. An implementation that throws here hands every group a denial-of-service button, and one that special-cases it wrongly gets a different aggregate nonce than its co-signers.',
    ],
  },
];

/** The featured cases, in a form the renderer can show even when a lookup misses. */
function featuredCases(results: KatResult[]): { spec: Featured; result?: KatResult }[] {
  return FEATURED.map((spec) => ({
    spec,
    result: results.find((r) => r.group === spec.group && r.index === spec.index),
  }));
}

/**
 * Expected vs. produced. Through `field` so the hex cases follow the page's
 * byte-display switch and the error-string cases print as the prose they are.
 */
function katFields(r: KatResult): HTMLElement[] {
  return [
    field('Expected', r.expected),
    field('This implementation produced', r.actual),
  ];
}

function passPill(pass: boolean): HTMLElement {
  return h(
    'span',
    { class: `pill pill-${pass ? 'ok' : 'bad'}` },
    h('span', { 'aria-hidden': 'true' }, pass ? '✓ ' : '✕ '),
    pass ? 'pass' : 'FAIL',
  );
}

export function renderVectorsPanel(root: HTMLElement): void {
  const output = h('div', { class: 'output' });

  root.append(
    panelIntro(
      'Checked against the specification’s own bytes',
      'An implementation that agrees with itself proves nothing. These are the official BIP-327 test vectors, taken verbatim from the Bitcoin BIPs repository, run against this page’s code every time you load it.',
      'They cover the accepting cases and — more usefully — every malformed-input case the spec enumerates: keys that are not curve points, keys whose x exceeds the field size, nonces with a bad prefix byte, partial signatures larger than the group order, out-of-range tweaks, and a signer trying to sign for a key list it is not in. Each of those must be REJECTED, and rejected for the right reason.',
    ),
    output,
  );

  let results: KatResult[];
  try {
    results = runAllVectors();
  } catch (err) {
    output.append(
      verdict('fail', `the vector runner itself failed — ${(err as Error).message}`, 'Error'),
    );
    return;
  }
  const summary = katSummary(results);

  clear(output);
  output.append(
    verdict(
      summary.failed === 0 ? 'pass' : 'fail',
      `${summary.passed} of ${summary.total} BIP-327 vectors pass — ${summary.accept} that must be accepted, ${summary.reject} that must be rejected`,
      summary.failed === 0 ? 'All pass' : `${summary.failed} failing`,
    ),
  );

  output.append(
    h(
      'p',
      { class: 'help' },
      'This tab is implementation evidence, not a sixth lesson. It establishes conformance to BIP-327 on the specification’s own inputs — which is a strong claim about the protocol logic, and says nothing about timing side channels, nonce storage, or whether the system around this code is safe.',
    ),
  );

  output.append(
    h(
      'section',
      { class: 'kat-featured', id: 'kat-featured' },
      h('h3', {}, 'Three cases worth reading'),
      h(
        'p',
        { class: 'help' },
        `Every one of the ${summary.total} cases is in the tables below. These three are the ones that change how you would write an implementation — and two of them are places where the obvious behaviour is the wrong one.`,
      ),
      ...featuredCases(results).map(({ spec, result }) =>
        h(
          'article',
          // A missing case is a failure, not a blank: the card stays, coloured bad.
          { class: `kat-feature ${result?.pass ? 'kat-ok' : 'kat-bad'}` },
          h('h4', {}, spec.title, passPill(result?.pass ?? false)),
          result
            ? h(
                'p',
                { class: 'kat-feature-case' },
                h('span', { class: 'kat-kind' }, result.kind === 'accept' ? 'MUST ACCEPT' : 'MUST REJECT'),
                ' ',
                h('span', {}, result.what),
              )
            : h(
                'p',
                { class: 'kat-feature-case' },
                `case ${spec.group} #${spec.index} was not found in the vector run — the vector files may have changed`,
              ),
          h('p', { class: 'kat-why' }, ...spec.why),
          ...(result ? katFields(result) : []),
        ),
      ),
    ),
  );

  for (const group of KAT_GROUPS) {
    const rows = results.filter((r) => r.group === group.id);
    const failed = rows.filter((r) => !r.pass).length;
    output.append(
      h(
        'section',
        { class: 'kat-group' },
        h(
          'h3',
          {},
          group.title,
          h(
            'span',
            { class: `pill pill-${failed === 0 ? 'ok' : 'bad'}` },
            h('span', { 'aria-hidden': 'true' }, failed === 0 ? '✓ ' : '✕ '),
            failed === 0 ? `${rows.length}/${rows.length} pass` : `${failed} failing`,
          ),
        ),
        h('p', { class: 'help' }, group.blurb),
        h('p', { class: 'kat-file' }, h('code', {}, `bip-0327/vectors/${group.file}`)),
        h(
          'div',
          { class: 'kat-list' },
          ...rows.map((r) =>
            h(
              'details',
              { class: `kat-item ${r.pass ? 'kat-ok' : 'kat-bad'}` },
              h(
                'summary',
                {},
                passPill(r.pass),
                h('span', { class: 'kat-kind' }, r.kind === 'accept' ? 'must accept' : 'must reject'),
                h('span', { class: 'kat-case' }, r.what),
              ),
              h('div', { class: 'kat-body' }, ...katFields(r)),
            ),
          ),
        ),
      ),
    );
  }

  output.append(
    disclosure(
      'What a green table does and does not prove',
      h(
        'p',
        {},
        'It proves the arithmetic matches BIP-327 on the specification’s inputs, including its rejection cases. That is a strong statement about correctness of the protocol logic.',
      ),
      h(
        'p',
        {},
        'It says nothing about timing side channels, about how secret nonces are stored between rounds, or about the security of any system built around this code. This implementation uses ordinary JavaScript BigInt arithmetic and is not constant-time. Not production crypto — a teaching demo. For real signing, use an audited implementation such as libsecp256k1.',
      ),
      h(
        'p',
        {},
        'Two vector groups exercise machinery this lab implements but does not put on stage: tweaking (the step that turns an aggregate key into a Taproot output key — see ',
        labLink('crypto-lab-bitcoin-script', 'crypto-lab-bitcoin-script'),
        ') and deterministic signing. They are run here because passing them is evidence the whole session-context derivation is right, not just the paths the exhibits happen to walk.',
      ),
    ),
    note(
      'info',
      'Vector source: ',
      h(
        'a',
        {
          href: 'https://github.com/bitcoin/bips/tree/master/bip-0327/vectors',
          target: '_blank',
          rel: 'noopener noreferrer',
        },
        'bitcoin/bips · bip-0327/vectors',
      ),
      '. The same runners drive this table and the Vitest suite that gates the deploy.',
    ),
  );
}
