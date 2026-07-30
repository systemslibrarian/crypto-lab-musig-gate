/**
 * The BIP-327 known-answer tests, executed in the browser on load.
 *
 * This table is not a report of a test run somewhere else — the runners in
 * ../musig/vectors.ts execute here, in this tab, against the same code the other
 * exhibits use. The same functions back the Vitest suite, so a green table and a
 * green CI run are the same claim.
 */
import { clear, disclosure, h, labLink, note, panelIntro, verdict } from './dom.js';
import { KAT_GROUPS, type KatResult, katSummary, runAllVectors } from '../musig/vectors.js';

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
                h(
                  'span',
                  { class: `pill pill-${r.pass ? 'ok' : 'bad'}` },
                  h('span', { 'aria-hidden': 'true' }, r.pass ? '✓ ' : '✕ '),
                  r.pass ? 'pass' : 'FAIL',
                ),
                h('span', { class: 'kat-kind' }, r.kind === 'accept' ? 'must accept' : 'must reject'),
                h('span', { class: 'kat-case' }, r.what),
              ),
              h(
                'div',
                { class: 'kat-body' },
                h(
                  'div',
                  { class: 'field' },
                  h('span', { class: 'field-label' }, 'Expected'),
                  h('code', { class: 'field-value' }, r.expected),
                ),
                h(
                  'div',
                  { class: 'field' },
                  h('span', { class: 'field-label' }, 'This implementation produced'),
                  h('code', { class: 'field-value' }, r.actual),
                ),
              ),
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
