import './style.css';
import { resetPredictions } from './ui/dom.js';
import { type PanelKey, mountTour } from './ui/tour.js';
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

function ensureRendered(key: PanelKey): void {
  if (rendered.has(key)) return;
  renderers[key](panelEl(key));
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

/**
 * The guided tour sits above the tabs and drives them. It is mounted before the
 * initial tab selection so a resumed tour can take over from the default panel.
 */
const tourHost = document.getElementById('tour-host');
if (tourHost) {
  mountTour(tourHost, selectTab, () => {
    // "Start over" means the whole lesson, not one panel: drop recorded predictions
    // and re-render every exhibit from scratch.
    resetPredictions();
    for (const key of rendered) {
      const el = panelEl(key);
      el.replaceChildren();
      renderers[key](el);
    }
  });
}

/** #keyagg / #rogue / #nonce / #vectors deep-link straight to an exhibit. */
function openFromHash(): boolean {
  const key = location.hash.replace(/^#/, '') as PanelKey;
  if (!(key in renderers)) return false;
  selectTab(key);
  return true;
}

if (!openFromHash()) selectTab('session');
window.addEventListener('hashchange', openFromHash);
