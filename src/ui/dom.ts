/** Tiny, dependency-free DOM helpers shared by the panels. */

type Attrs = Record<string, string | number | boolean | EventListener | undefined>;
type Child = Node | string | null | undefined;

/** Hyperscript: h('button', { class: 'x', onclick: fn }, 'label'). */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
    } else if (key === 'class') {
      node.className = String(value);
    } else if (value === true) {
      node.setAttribute(key, '');
    } else {
      node.setAttribute(key, String(value));
    }
  }
  for (const c of children) {
    if (c == null) continue;
    node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

export function clear(node: HTMLElement): void {
  node.replaceChildren();
}

/** A labelled read-only value shown as wrapping monospace (no scroll region needed). */
export function field(
  label: string,
  value: string,
  opts: { mono?: boolean; sub?: string } = {},
): HTMLElement {
  return h(
    'div',
    { class: 'field' },
    h(
      'span',
      { class: 'field-label' },
      label,
      opts.sub ? h('span', { class: 'field-sub' }, ` ${opts.sub}`) : null,
    ),
    h('code', { class: opts.mono === false ? 'field-value plain' : 'field-value' }, value),
  );
}

/**
 * A pass/fail/alarm verdict: icon + text + colour, never colour alone (WCAG 1.4.1).
 *
 * `alarm` is for "the system accepted something it should not have" — a successful
 * forgery is an alarm, not a green success. `word` overrides the leading label,
 * because colour here tracks system integrity rather than a function's return
 * value: an attack that failed is a PASS, and calling it "Valid" would be wrong.
 */
export function verdict(
  state: 'pass' | 'fail' | 'alarm',
  text: string,
  word?: string,
): HTMLElement {
  const icon = state === 'pass' ? '✓' : state === 'alarm' ? '⚠' : '✕';
  const label = word ?? (state === 'pass' ? 'Valid' : state === 'alarm' ? 'Alarm' : 'Rejected');
  return h(
    'div',
    { class: `verdict verdict-${state}`, role: 'status' },
    h('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, icon),
    h('span', { class: 'verdict-word' }, `${label}: `),
    h('span', {}, text),
  );
}

/** Section heading + intro paragraph(s) for a panel. */
export function panelIntro(title: string, ...paras: (string | HTMLElement)[]): HTMLElement {
  return h(
    'div',
    { class: 'panel-intro' },
    h('h2', {}, title),
    ...paras.map((p) => (typeof p === 'string' ? h('p', {}, p) : p)),
  );
}

/** A scoping / caveat / danger note. */
export function note(kind: 'info' | 'danger' | 'caveat', ...children: Child[]): HTMLElement {
  return h('p', { class: `callout callout-${kind}` }, ...children);
}

/** Inline code. */
export function code(text: string): HTMLElement {
  return h('code', {}, text);
}

/** An external link to a sibling lab. */
export function labLink(slug: string, text = slug): HTMLElement {
  return h(
    'a',
    {
      href: `https://systemslibrarian.github.io/${slug}/`,
      target: '_blank',
      rel: 'noopener noreferrer',
    },
    text,
  );
}

/** Middle-truncate a long hex string for compact display. */
export function short(hex: string, keep = 8): string {
  if (hex.length <= keep * 2 + 1) return hex;
  return `${hex.slice(0, keep)}…${hex.slice(-keep)}`;
}

/** A collapsible details block. */
export function disclosure(summary: string, ...children: Child[]): HTMLElement {
  return h(
    'details',
    { class: 'disclose' },
    h('summary', {}, summary),
    h('div', { class: 'disclose-body' }, ...children),
  );
}

/**
 * "Compute both sides and compare" — render two values with an explicit
 * byte-for-byte equality verdict rather than asserting they match.
 */
export function bothSides(
  equation: string,
  left: { label: string; value: string },
  right: { label: string; value: string },
): HTMLElement {
  const equal = left.value === right.value;
  return h(
    'div',
    { class: 'both-sides' },
    h('p', { class: 'both-sides-eq' }, equation),
    field(left.label, left.value),
    field(right.label, right.value),
    verdict(
      equal ? 'pass' : 'fail',
      equal ? 'the two sides match exactly' : 'the two sides differ',
      equal ? 'Match' : 'Mismatch',
    ),
  );
}

/**
 * A "predict before you reveal" check: one misconception, a couple of choices, an
 * immediate explanation. No score or gamification; the lab is fully usable whether
 * or not it is answered.
 */
export function learnerCheck(
  question: string,
  options: { label: string; correct: boolean }[],
  explanation: string,
): HTMLElement {
  const feedback = h('div', { class: 'check-feedback', role: 'status', 'aria-live': 'polite' });
  const buttons = options.map((o) =>
    h(
      'button',
      {
        type: 'button',
        class: 'btn btn-ghost check-opt',
        onclick: () => {
          clear(feedback);
          feedback.append(
            h(
              'span',
              { class: `pill pill-${o.correct ? 'ok' : 'bad'}` },
              h('span', { 'aria-hidden': 'true' }, o.correct ? '✓ ' : '✕ '),
              o.correct ? 'Correct' : 'Not quite',
            ),
            h('p', { class: 'check-explain' }, explanation),
          );
        },
      },
      o.label,
    ),
  );
  return h(
    'details',
    { class: 'learner-check' },
    h('summary', {}, 'Quick check'),
    h(
      'div',
      { class: 'check-body' },
      h('p', { class: 'check-q' }, question),
      h('div', { class: 'input-row', role: 'group', 'aria-label': question }, ...buttons),
      feedback,
    ),
  );
}

// --------------------------------------------------------------- predictions
//
// The difference between testing recognition and testing understanding is WHEN the
// question is asked. A question after the reveal asks "did you read that?"; the same
// question before it asks "what do you expect, and why?" — and then the experiment
// either confirms or contradicts the learner, which is the moment learning happens.
//
// So a prediction is deliberately NOT graded at the point of answering. It is
// recorded, the experiment runs, and a debrief elsewhere on the page reports whether
// the learner was right. The two halves are linked by id.

interface Recorded {
  chosen: number;
  correct: boolean;
  label: string;
}

const predictions = new Map<string, Recorded>();
const predictionListeners = new Map<string, Set<() => void>>();

function notify(id: string): void {
  for (const fn of predictionListeners.get(id) ?? []) fn();
}

/** What the learner predicted, if anything. Exposed for the exit check. */
export function getPrediction(id: string): Recorded | undefined {
  return predictions.get(id);
}

/** Clear every recorded prediction — used when the guided tour restarts. */
export function resetPredictions(): void {
  const ids = [...predictions.keys()];
  predictions.clear();
  for (const id of ids) notify(id);
}

/**
 * Ask before computing. Records the choice and acknowledges it, but does NOT say
 * whether it was right — that is the experiment's job, reported by `predictionDebrief`.
 */
export function prediction(
  id: string,
  question: string,
  options: { label: string; correct: boolean }[],
): HTMLElement {
  const status = h('div', { class: 'predict-status', role: 'status', 'aria-live': 'polite' });
  const buttons = options.map((o, i) =>
    h(
      'button',
      {
        type: 'button',
        class: 'btn btn-ghost predict-opt',
        onclick: () => {
          predictions.set(id, { chosen: i, correct: o.correct, label: o.label });
          for (const b of buttons) b.classList.toggle('predict-chosen', b === buttons[i]);
          clear(status);
          status.append(
            h('span', { class: 'pill pill-neutral' }, 'Prediction recorded'),
            h(
              'p',
              { class: 'help' },
              'Now run the experiment below. The result will tell you whether you were right.',
            ),
          );
          notify(id);
        },
      },
      o.label,
    ),
  ) as HTMLButtonElement[];

  return h(
    'div',
    { class: 'predict' },
    h('span', { class: 'predict-tag' }, 'PREDICT FIRST'),
    h('p', { class: 'predict-q' }, question),
    h('div', { class: 'predict-opts', role: 'group', 'aria-label': question }, ...buttons),
    status,
  );
}

/**
 * The other half: after the experiment has run, say whether the prediction held and
 * why. Renders nothing until a prediction exists, so it never spoils the answer.
 */
export function predictionDebrief(id: string, explanation: string): HTMLElement {
  const box = h('div', { class: 'predict-debrief', role: 'status', 'aria-live': 'polite' });
  const paint = (): void => {
    clear(box);
    const got = predictions.get(id);
    if (!got) {
      box.append(
        h(
          'p',
          { class: 'help' },
          'You did not record a prediction for this one — scroll up and commit to an answer before running it again; being wrong on purpose is how the idea sticks.',
        ),
      );
      return;
    }
    box.append(
      h(
        'span',
        { class: `pill pill-${got.correct ? 'ok' : 'bad'}` },
        h('span', { 'aria-hidden': 'true' }, got.correct ? '✓ ' : '✕ '),
        got.correct ? 'Your prediction was right' : 'Your prediction was wrong',
      ),
      h('p', { class: 'check-explain' }, `You predicted: ${got.label}`),
      h('p', { class: 'check-explain' }, explanation),
    );
  };
  const set = predictionListeners.get(id) ?? new Set();
  set.add(paint);
  predictionListeners.set(id, set);
  paint();
  return box;
}

/**
 * A visible question — unlike `learnerCheck`, which hides in a disclosure. Used for
 * the exit check, where the whole point is that the learner cannot skip past it.
 */
export function exitQuestion(
  question: string,
  options: { label: string; correct: boolean }[],
  explanation: string,
): HTMLElement {
  const feedback = h('div', { class: 'check-feedback', role: 'status', 'aria-live': 'polite' });
  const buttons = options.map((o) =>
    h(
      'button',
      {
        type: 'button',
        class: 'btn btn-ghost check-opt',
        onclick: () => {
          clear(feedback);
          feedback.append(
            h(
              'span',
              { class: `pill pill-${o.correct ? 'ok' : 'bad'}` },
              h('span', { 'aria-hidden': 'true' }, o.correct ? '✓ ' : '✕ '),
              o.correct ? 'Correct' : 'Not quite',
            ),
            h('p', { class: 'check-explain' }, explanation),
          );
        },
      },
      o.label,
    ),
  );
  return h(
    'div',
    { class: 'exit-q' },
    h('p', { class: 'check-q' }, question),
    h('div', { class: 'input-row', role: 'group', 'aria-label': question }, ...buttons),
    feedback,
  );
}

/**
 * Match each threat to the thing that actually defends against it — including the
 * row where the honest answer is "nothing in this protocol does".
 *
 * Selects rather than drag-and-drop: a native control is keyboard-operable, works on
 * a phone, and needs no custom accessibility work to be correct.
 */
export function matchingTask(opts: {
  idPrefix: string;
  rows: { threat: string; correct: string }[];
  choices: string[];
}): HTMLElement {
  const selects: HTMLSelectElement[] = [];
  const feedback = h('div', { class: 'check-feedback', role: 'status', 'aria-live': 'polite' });

  const body = opts.rows.map((row, i) => {
    const id = `${opts.idPrefix}-${i}`;
    const select = h('select', { id, class: 'mono-input styled-select' }) as HTMLSelectElement;
    select.append(h('option', { value: '' }, 'Choose a defence…') as HTMLOptionElement);
    for (const c of opts.choices) select.append(h('option', { value: c }, c) as HTMLOptionElement);
    selects.push(select);
    return h(
      'div',
      { class: 'match-row' },
      h('label', { for: id, class: 'match-threat' }, row.threat),
      select,
    );
  });

  const check = h(
    'button',
    {
      type: 'button',
      class: 'btn btn-primary',
      onclick: () => {
        clear(feedback);
        const wrong = opts.rows.filter((row, i) => selects[i].value !== row.correct);
        const unanswered = selects.filter((sel) => sel.value === '').length;
        selects.forEach((sel, i) => {
          sel.classList.toggle('match-ok', sel.value !== '' && sel.value === opts.rows[i].correct);
          sel.classList.toggle('match-bad', sel.value !== '' && sel.value !== opts.rows[i].correct);
        });
        feedback.append(
          h(
            'span',
            { class: `pill pill-${wrong.length === 0 ? 'ok' : 'bad'}` },
            h('span', { 'aria-hidden': 'true' }, wrong.length === 0 ? '✓ ' : '✕ '),
            wrong.length === 0
              ? 'All four matched'
              : `${wrong.length} of ${opts.rows.length} not matched yet${unanswered ? ` (${unanswered} left blank)` : ''}`,
          ),
          ...wrong.map((row) =>
            h('p', { class: 'check-explain' }, `“${row.threat}” → ${row.correct}`),
          ),
        );
      },
    },
    'Check my answers',
  );

  return h('div', { class: 'match-task' }, ...body, h('div', { class: 'action-row' }, check), feedback);
}

/**
 * The closing line of a panel: what this established, and what it makes you ask next.
 * Without these the exhibits read as five peers rather than one argument.
 */
export function bridge(
  established: string,
  next: string,
  action?: { label: string; onClick: () => void },
): HTMLElement {
  return h(
    'aside',
    { class: 'bridge', 'aria-label': 'Where this leads' },
    h(
      'p',
      { class: 'bridge-line' },
      h('span', { class: 'bridge-label' }, 'What this established: '),
      established,
    ),
    h(
      'p',
      { class: 'bridge-line' },
      h('span', { class: 'bridge-label' }, 'What it makes you ask: '),
      next,
    ),
    action
      ? h(
          'button',
          { type: 'button', class: 'btn btn-primary bridge-btn', onclick: action.onClick },
          action.label,
        )
      : null,
  );
}

/**
 * Jargon scaffolding: a collapsed definition list a newcomer can open the moment a
 * term stops making sense, without the terms being pre-chewed for readers who
 * already know them.
 */
export function glossary(entries: { term: string; plain: string; formal?: string }[]): HTMLElement {
  return h(
    'details',
    { class: 'disclose glossary' },
    h('summary', {}, 'Glossary — the words this page uses'),
    h(
      'dl',
      { class: 'glossary-body' },
      ...entries.flatMap((e) => [
        h('dt', {}, e.term),
        h(
          'dd',
          {},
          e.plain,
          e.formal ? h('span', { class: 'glossary-formal' }, ` ${e.formal}`) : null,
        ),
      ]),
    ),
  );
}

/** A labelled text input with help text. */
export function textControl(opts: {
  id: string;
  label: string;
  value: string;
  help?: string;
  rows?: number;
  onInput?: (value: string) => void;
}): { wrap: HTMLElement; input: HTMLTextAreaElement | HTMLInputElement } {
  const input = (
    opts.rows
      ? h('textarea', {
          id: opts.id,
          class: 'mono-input msg-input',
          rows: opts.rows,
          spellcheck: 'false',
        })
      : h('input', { id: opts.id, class: 'mono-input', type: 'text', spellcheck: 'false' })
  ) as HTMLTextAreaElement | HTMLInputElement;
  input.value = opts.value;
  if (opts.onInput) input.addEventListener('input', () => opts.onInput!(input.value));
  return {
    wrap: h(
      'div',
      { class: 'control' },
      h('label', { for: opts.id }, opts.label),
      input,
      opts.help ? h('p', { class: 'help' }, opts.help) : null,
    ),
    input,
  };
}

/** A scrollable region, wired for keyboard access as the a11y gate requires. */
export function scrollRegion(label: string, ...children: Child[]): HTMLElement {
  return h(
    'div',
    { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': label },
    ...children,
  );
}
