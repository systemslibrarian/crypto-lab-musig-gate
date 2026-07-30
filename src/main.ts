import './style.css';
import { byteModeControl, h, note, panelIntro, resetPredictions, srOnly, verdict } from './ui/dom.js';
import { type PanelKey, type TourProgress, mountTour } from './ui/tour.js';
import { renderSessionPanel } from './ui/sessionPanel.js';
import { renderKeyAggPanel } from './ui/keyaggPanel.js';
import { renderRoguePanel } from './ui/roguePanel.js';
import { renderNoncePanel } from './ui/noncePanel.js';
import { renderVectorsPanel } from './ui/vectorsPanel.js';

const renderers: Record<PanelKey, (root: HTMLElement) => void> = {
  session: renderSessionPanel,
  keyagg: renderKeyAggPanel,
  rogue: renderRoguePanel,
  nonce: renderNoncePanel,
  vectors: renderVectorsPanel,
};

const rendered = new Set<PanelKey>();

function panelEl(key: PanelKey): HTMLElement {
  return document.getElementById(`panel-${key}`) as HTMLElement;
}

/**
 * Render a panel, and say so out loud if it cannot be rendered.
 *
 * Without this a throwing exhibit leaves an empty tab and a message only in the
 * devtools console — the learner sees a blank page and has no idea whether that is
 * the demo or their browser. Real causes exist: WebCrypto is absent on an insecure
 * origin, and every panel generates keys the moment it renders.
 *
 * The panel is marked rendered either way, so a failure costs one blank exhibit
 * rather than re-throwing on every tab switch, and the error is still re-reported to
 * the console for anyone who wants the stack.
 */
function ensureRendered(key: PanelKey): void {
  if (rendered.has(key)) return;
  const el = panelEl(key);
  try {
    renderers[key](el);
  } catch (err) {
    console.error(`panel "${key}" failed to render`, err);
    el.replaceChildren(
      panelIntro(
        'This exhibit could not run',
        'Something in this panel threw while rendering. That is a bug in this page or a capability its browser is missing — not a property of MuSig2, and not a result you should read anything into.',
      ),
      verdict('fail', (err as Error)?.message ?? String(err), 'Error'),
      note(
        'caveat',
        'The most common cause is a browser without WebCrypto, which this lab needs to generate keys and nonces — it is unavailable on pages served over plain HTTP from anything other than localhost. Reloading over HTTPS usually fixes it.',
      ),
    );
  }
  rendered.add(key);
}

function selectTab(key: PanelKey): void {
  for (const tab of document.querySelectorAll<HTMLButtonElement>('.tab-btn')) {
    const isActive = tab.dataset.panel === key;
    tab.setAttribute('aria-selected', String(isActive));
    tab.tabIndex = isActive ? 0 : -1;
    tab.classList.toggle('active', isActive);
    panelEl(tab.dataset.panel as PanelKey).hidden = !isActive;
  }
  ensureRendered(key);
}

function wireTabs(): void {
  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'));
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectTab(tab.dataset.panel as PanelKey));
    // Roving-tabindex arrow-key navigation across the tablist (WAI-ARIA pattern).
    tab.addEventListener('keydown', (e) => {
      let next = -1;
      if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabs.length - 1;
      if (next >= 0) {
        e.preventDefault();
        tabs[next].focus();
        selectTab(tabs[next].dataset.panel as PanelKey);
      }
    });
  });
}

wireTabs();

/** One global control for hex verbosity, so nothing has to be expanded one at a time. */
const byteHost = document.getElementById('byte-mode-host');
if (byteHost) byteHost.append(byteModeControl());

/**
 * The guided tour sits above the tabs and drives them. It is mounted before the
 * initial tab selection so a resumed tour can take over from the default panel.
 */
/**
 * Captured before the tour mounts, because mounting renders, rendering reports
 * progress, and reporting progress rewrites the hash — which would destroy an
 * incoming `#step-6` before anything had a chance to read it.
 */
const initialHash = location.hash;
let routed = false;

const tourHost = document.getElementById('tour-host');
const tour = tourHost
  ? mountTour(
      tourHost,
      selectTab,
      () => {
        // "Start over" means the whole lesson, not one panel: drop recorded predictions
        // and re-render every exhibit from scratch.
        resetPredictions();
        for (const key of rendered) {
          const el = panelEl(key);
          el.replaceChildren();
          renderers[key](el);
        }
      },
      (progress) => {
        markTourProgress(progress);
        // Not before the initial route: see `initialHash`.
        if (routed) syncHash(progress);
      },
    )
  : null;

/**
 * While the tour runs, the tab strip becomes the lesson map: exhibits whose stops are
 * behind you are marked done.
 *
 * The mark is a tick AND a word — "done" is appended to each tab's accessible name
 * rather than being carried by colour and a glyph alone, so the state survives
 * greyscale and reaches a screen reader. Cleared entirely when the tour is not
 * running, because outside the lesson there is no order to be ahead or behind of.
 */
function markTourProgress(progress: TourProgress): void {
  for (const tab of document.querySelectorAll<HTMLButtonElement>('.tab-btn')) {
    const key = tab.dataset.panel as PanelKey;
    const done = progress.active && progress.done.has(key);
    tab.classList.toggle('tab-done', done);
    let tick = tab.querySelector('.tab-tick');
    if (done && !tick) {
      tick = h('span', { class: 'tab-tick' }, h('span', { 'aria-hidden': 'true' }, ' ✓'), srOnly(' done'));
      tab.append(tick);
    } else if (!done && tick) {
      tick.remove();
    }
  }
}

/**
 * Two kinds of deep link.
 *
 *   #rogue    — open an exhibit, for someone who wants that one thing.
 *   #step-4   — start the lesson at a stop, for someone teaching from it.
 *
 * The second is the reason the tour returns a controller at all. Being able to send
 * "read step 6" and have it open on step 6 is most of what makes a guided lesson
 * usable by a third party, and the alternative — "press Continue five times" — is
 * the kind of instruction that quietly does not get followed.
 */
const STEP_HASH = /^#step-(\d+)$/;

function openFromHash(hash: string = location.hash): boolean {
  const step = STEP_HASH.exec(hash);
  if (step && tour) {
    // 1-based in the URL because the interface counts stops from 1.
    tour.goto(Number(step[1]) - 1);
    return true;
  }
  const key = hash.replace(/^#/, '') as PanelKey;
  if (!(key in renderers)) return false;
  selectTab(key);
  return true;
}

/**
 * Keep the address bar on the current stop so copying the URL mid-lesson shares that
 * stop rather than the beginning.
 *
 * `replaceState`, not a hash assignment: ten Continues should not put ten entries in
 * the back button, and assigning `location.hash` would re-enter `openFromHash` and
 * fight the navigation that just happened.
 */
function syncHash(progress: TourProgress): void {
  const want = progress.active ? `#step-${progress.index + 1}` : '';
  const current = location.hash;
  if (want === current) return;
  // Leaving the lesson should not clobber an exhibit deep link the user typed.
  if (!want && !STEP_HASH.test(current)) return;
  history.replaceState(null, '', want || location.pathname + location.search);
}

if (!openFromHash(initialHash)) selectTab('session');
routed = true;
window.addEventListener('hashchange', () => openFromHash());
