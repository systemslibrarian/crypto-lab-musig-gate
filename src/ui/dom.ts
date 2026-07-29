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
      equal ? 'the two sides are byte-for-byte identical' : 'the two sides differ',
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
