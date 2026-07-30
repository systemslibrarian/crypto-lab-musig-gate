/**
 * The guided tour — the thing that turns five good exhibits into one lesson.
 *
 * Without it the tab bar presents `Signing Session | Key Aggregation | Rogue Key |
 * Why Two Nonces | Vectors` as five peers, and the learner has to work out for
 * themselves whether those are alternatives, prerequisites or chapters. The code and
 * the README know the causal order; this makes the interface know it too:
 *
 *     one key + one signature is useful
 *       → naive key aggregation is broken by rogue keys
 *       → coefficients repair it
 *       → naive one-nonce signing is broken by nonce control
 *       → two nonces and b repair it
 *       → the result is an ordinary BIP-340 signature
 *
 * The tabs stay exactly as they were, so deep links and free exploration still work.
 * The tour is an overlay on top of them, not a replacement: it selects a tab, scrolls
 * to the part of it that matters, and says what to do there.
 *
 * Progress lives in sessionStorage so a reload mid-lesson does not lose the thread,
 * and dies with the tab so the next visitor starts fresh.
 */
import { clear, h } from './dom.js';

export type PanelKey = 'session' | 'keyagg' | 'rogue' | 'nonce' | 'vectors';

export interface TourStop {
  /** Short imperative title — names the conceptual move, not the navigation. */
  title: string;
  panel: PanelKey;
  /** Element id to scroll to once the panel is showing. */
  anchor: string;
  /** What to do at this stop, in one or two sentences. */
  blurb: string;
  /**
   * A registered action to run before scrolling. Some anchors only exist once a
   * panel is in a particular state, and a tour that scrolls to nothing is worse
   * than no tour.
   */
  action?: string;
}

const actions = new Map<string, () => void>();

/**
 * Panels register the states the tour needs to be able to reach. Keeps `tour.ts`
 * ignorant of panel internals while still letting a stop guarantee its anchor exists.
 */
export function registerTourAction(name: string, fn: () => void): void {
  actions.set(name, fn);
}

/**
 * Ten stops. The shape is deliberate: promise, predict, run, break, repair, SEE the
 * repair, break, repair, return to the promise, prove you can transfer it.
 *
 * The "see the repair" stop was added after the rest: without it the tour showed
 * coefficients defeating the rogue-key attack — the attacker missing round after
 * round — without ever showing what a coefficient does to a key. That is the
 * difference between "it works" and "I know why", and the drawable F_127 group is
 * the only place on the page where the answer is a picture rather than more hex.
 * It also closed a hole in the tab strip's lesson map, where Key Aggregation was the
 * one teaching exhibit no stop ever reached.
 */
export const TOUR: TourStop[] = [
  {
    title: 'The promise',
    panel: 'session',
    anchor: 'tour-run',
    blurb:
      'Three signers, one message. Press "Show all steps" and watch n public keys become one key, n nonce pairs become one nonce, and n partial signatures become one signature.',
  },
  {
    title: 'Predict: can a verifier tell?',
    panel: 'session',
    anchor: 'tour-predict-indist',
    blurb:
      'Before you look at the answer, commit to one. A verifier is handed the finished signature and the aggregate key — is there anything in those bytes that reveals a group made them?',
  },
  {
    title: 'Read the session end to end',
    panel: 'session',
    anchor: 'tour-steps',
    blurb:
      'Walk the six steps. The two values worth understanding are a_i, which weights each key, and b, which weights the second nonce. Everything after this is about why those two exist.',
  },
  {
    title: 'Break naive key aggregation',
    panel: 'rogue',
    anchor: 'tour-rogue-predict',
    blurb:
      'Predict which aggregation rule a last-moving attacker can steer, then run the attack against Q = ΣP_i and watch a real verifier accept a forgery.',
  },
  {
    title: 'Repair the key rule',
    panel: 'rogue',
    anchor: 'tour-rogue-fixed',
    blurb:
      'Now run the identical attack against Q = Σa_i·P_i. The coefficients are what stop it, and the round-by-round table shows the attacker never converging.',
  },
  {
    title: 'See what a coefficient does',
    panel: 'keyagg',
    anchor: 'tour-keyagg-drawn',
    blurb:
      'You have now seen coefficients stop the attack, but not what they actually do to a key. Here is the same construction on a group small enough to draw: 127 points, each key marked, an arrow to where its coefficient sent it, and the naive sum landing somewhere else entirely.',
  },
  {
    title: 'Break naive nonce aggregation',
    panel: 'nonce',
    anchor: 'tour-nonce-predict',
    blurb:
      'Keys are safe now, but every signature also aggregates fresh nonces. Predict whether a last mover can steer a plain sum of them, then try it.',
  },
  {
    title: 'Repair the nonce rule',
    panel: 'nonce',
    anchor: 'tour-nonce-fixed',
    blurb:
      'Run the same move against R = R_1 + b·R_2. Watch b change every time the attacker changes its nonce — the target moves as they reach for it.',
  },
  {
    title: 'Back to the promise',
    panel: 'session',
    anchor: 'tour-blind',
    action: 'session:showAll',
    blurb:
      'Both naive designs are broken and both repairs are in place. Here is the payoff: one of these two signatures came from a group and one from a single signer. Pick one.',
  },
  {
    title: 'Prove you can use it',
    panel: 'session',
    anchor: 'tour-transfer',
    blurb:
      'The last step is not a recap. It is a scenario you have not seen, to check the idea transfers.',
  },
];

const STORAGE_KEY = 'musig-gate-tour';

interface TourState {
  active: boolean;
  index: number;
}

function load(): TourState {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return { active: false, index: 0 };
    const parsed = JSON.parse(raw) as TourState;
    if (typeof parsed.index !== 'number' || parsed.index < 0 || parsed.index >= TOUR.length) {
      return { active: false, index: 0 };
    }
    return { active: Boolean(parsed.active), index: parsed.index };
  } catch {
    return { active: false, index: 0 };
  }
}

function save(state: TourState): void {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    // Private-mode storage refusal is not a reason to break the lesson.
  }
}

export interface TourController {
  start(): void;
  stop(): void;
  goto(index: number): void;
  next(): void;
  isActive(): boolean;
  /** Jump straight to the stop that sits on a given anchor, if the tour is running. */
  focusAnchor(anchor: string): void;
}

/**
 * How far the lesson has got, per exhibit — enough for the tab strip to read as the
 * lesson map rather than five unrelated destinations.
 *
 * `done` means every stop in that panel is behind us. Reported rather than applied
 * here: `tour.ts` still knows nothing about tabs, and whoever owns them decides how
 * to show it.
 */
export interface TourProgress {
  active: boolean;
  current: PanelKey | null;
  done: Set<PanelKey>;
}

function progressAt(state: TourState): TourProgress {
  const done = new Set<PanelKey>();
  if (state.active) {
    for (const panel of new Set(TOUR.map((s) => s.panel))) {
      const stops = TOUR.map((s, i) => ({ s, i })).filter(({ s }) => s.panel === panel);
      if (stops.every(({ i }) => i < state.index)) done.add(panel);
    }
  }
  return {
    active: state.active,
    current: state.active ? TOUR[state.index].panel : null,
    done,
  };
}

/**
 * Mount the tour bar and return a controller.
 *
 * `selectTab` is injected rather than imported so this module has no opinion about
 * how tabs work — it only needs a way to make a panel visible before scrolling.
 */
export function mountTour(
  host: HTMLElement,
  selectTab: (panel: PanelKey) => void,
  onReset: () => void,
  onProgress: (progress: TourProgress) => void = () => {},
): TourController {
  let state = load();

  const label = h('span', { class: 'tour-label' });
  const blurb = h('p', { class: 'tour-blurb' });
  const dots = h('div', { class: 'tour-dots', 'aria-hidden': 'true' });
  const continueBtn = h(
    'button',
    { type: 'button', class: 'btn btn-primary', onclick: () => next() },
    'Continue',
  ) as HTMLButtonElement;

  const bar = h(
    'section',
    { class: 'tour-bar', id: 'tour-bar', 'aria-label': 'Guided tour', role: 'region' },
    h(
      'div',
      { class: 'tour-head' },
      h('span', { class: 'tour-tag' }, 'GUIDED TOUR'),
      label,
      h(
        'div',
        { class: 'tour-actions' },
        continueBtn,
        h(
          'button',
          {
            type: 'button',
            class: 'btn btn-ghost',
            onclick: () => {
              onReset();
              goto(0);
            },
          },
          'Start over',
        ),
        h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => stop() }, 'Exit tour'),
      ),
    ),
    blurb,
    dots,
  );

  const startBtn = h(
    'button',
    { type: 'button', class: 'btn btn-primary tour-start-btn', onclick: () => start() },
    'Start the guided tour',
  );
  const invitation = h(
    'section',
    { class: 'tour-invite', id: 'tour-invite' },
    h(
      'div',
      { class: 'tour-invite-main' },
      h('h2', { class: 'tour-invite-title' }, 'Run the 3-signer experiment'),
      h(
        'p',
        { class: 'tour-invite-promise' },
        'In about ten minutes you will produce one ordinary signature from three signers, break two designs that look obviously correct, and be able to explain both fixes.',
      ),
    ),
    h(
      'div',
      { class: 'tour-invite-actions' },
      startBtn,
      h('p', { class: 'help' }, 'Or ignore it and explore the five exhibits in any order.'),
    ),
  );

  host.append(invitation, bar);

  function render(): void {
    bar.hidden = !state.active;
    invitation.hidden = state.active;
    onProgress(progressAt(state));
    if (!state.active) return;
    const stop = TOUR[state.index];
    label.textContent = `Step ${state.index + 1} of ${TOUR.length}: ${stop.title}`;
    blurb.textContent = stop.blurb;
    continueBtn.textContent =
      state.index === TOUR.length - 1 ? 'Finish' : `Continue → ${TOUR[state.index + 1].title}`;
    clear(dots);
    TOUR.forEach((_, i) => {
      dots.append(
        h('span', {
          class: `tour-dot${i < state.index ? ' tour-dot-done' : ''}${i === state.index ? ' tour-dot-now' : ''}`,
        }),
      );
    });
  }

  function reveal(): void {
    const stop = TOUR[state.index];
    selectTab(stop.panel);
    if (stop.action) actions.get(stop.action)?.();
    // The panel has to be visible before the anchor can be measured.
    requestAnimationFrame(() => {
      const target = document.getElementById(stop.anchor);
      if (target) {
        target.scrollIntoView({ block: 'center', behavior: 'smooth' });
        target.classList.add('tour-flash');
        setTimeout(() => target.classList.remove('tour-flash'), 1400);
      }
    });
  }

  function goto(index: number): void {
    state = { active: true, index: Math.max(0, Math.min(index, TOUR.length - 1)) };
    save(state);
    render();
    reveal();
  }

  function start(): void {
    goto(state.index);
  }

  function stop(): void {
    state = { active: false, index: state.index };
    save(state);
    render();
    invitation.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }

  function next(): void {
    if (state.index >= TOUR.length - 1) {
      stop();
      return;
    }
    goto(state.index + 1);
  }

  render();
  if (state.active) reveal();

  return {
    start,
    stop,
    goto,
    next,
    isActive: () => state.active,
    focusAnchor(anchor: string) {
      const i = TOUR.findIndex((s) => s.anchor === anchor);
      if (i >= 0) goto(i);
    },
  };
}
