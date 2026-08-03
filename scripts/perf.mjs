/**
 * The browser half of the performance table in the README.
 *
 * Published performance numbers are worth exactly as much as their reproducibility,
 * so this is the harness that produced them rather than a note about what someone
 * once saw. Run `npm run perf`; it builds nothing (use the current `dist/`), serves
 * the production build, drives Chromium, and prints the table in Markdown ready to
 * paste back.
 *
 * Method, applied identically to every row:
 *   - the production build, served by `vite preview` — what actually ships;
 *   - a fresh page per run, so nothing is measured warm by accident;
 *   - timing wrapped around the synchronous work between the click and the result,
 *     which is the thing a user waits for;
 *   - WARMUP runs discarded, then RUNS measured; median reported, with the full
 *     spread, because a row whose min and max differ by 2x is not a number.
 *
 * The two forgeries are the exception and say so: they yield to paint a "searching…"
 * state before blocking, so a click is not the unit of work. They time their own
 * compute and display it, and this reads that — the same figure a visitor sees.
 *
 * Load matters more than anything else here. A first attempt at these numbers, taken
 * while the test suites were running, spread a single row across 121-245 ms. The
 * script refuses to report if the machine is busy.
 */
import { spawn } from 'node:child_process';
import { cpus, loadavg } from 'node:os';
import { chromium } from '@playwright/test';

const PORT = 4716;
const BASE = `http://localhost:${PORT}/crypto-lab-musig-gate/`;
const RUNS = 11;
const WARMUP = 2;
/** Above this 1-minute load average per core, the numbers are noise. */
const MAX_LOAD_PER_CORE = 0.4;

const median = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const ms = (n) => (n >= 100 ? Math.round(n) : Math.round(n * 10) / 10);

function checkLoad() {
  const cores = cpus().length;
  const [one] = loadavg();
  const perCore = one / cores;
  console.log(`machine: ${cores} cores, 1-min load ${one.toFixed(2)} (${perCore.toFixed(2)}/core)`);
  if (perCore > MAX_LOAD_PER_CORE) {
    console.error(
      `\nRefusing to measure: load is ${perCore.toFixed(2)} per core, above ${MAX_LOAD_PER_CORE}.\n` +
        `Close what is running and try again — numbers taken under load are not numbers.`,
    );
    process.exit(1);
  }
}

async function serve() {
  const proc = spawn('npx', ['vite', 'preview', '--port', String(PORT), '--strictPort'], {
    stdio: 'ignore',
  });
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(BASE);
      if (res.ok) return proc;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  proc.kill();
  throw new Error(`preview server did not come up on ${PORT}`);
}

const rows = [];
function record(label, times, note = '') {
  const m = median(times);
  rows.push({ label, median: m, min: Math.min(...times), max: Math.max(...times), note });
  console.log(
    `  ${label.padEnd(52)} ${String(ms(m)).padStart(6)} ms   [${ms(Math.min(...times))}–${ms(Math.max(...times))}]`,
  );
}

/** Time the synchronous handler behind a button, once per fresh page. */
async function timeClick(browser, label, prep, findBtn, note) {
  const times = [];
  for (let i = 0; i < RUNS + WARMUP; i++) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    await page.goto(BASE);
    if (prep) await prep(page);
    const t = await page.evaluate((src) => {
      const btn = new Function(`return (${src})`)();
      const t0 = performance.now();
      btn.click();
      return performance.now() - t0;
    }, findBtn);
    await page.close();
    if (i >= WARMUP) times.push(t);
  }
  record(label, times, note);
}

/** Read the figure the page measured for itself. */
async function readSelfTimed(browser, label, prep, buttonText, statLabel, runs = 7) {
  const times = [];
  for (let i = 0; i < runs + 1; i++) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    await page.goto(BASE);
    await page.locator('#tab-nonce').click();
    await page.locator('#tour-advanced > summary').click();
    if (prep) await prep(page);
    await page.locator('#panel-nonce button', { hasText: buttonText }).click();
    const stat = page.locator('#panel-nonce .wagner-stat', { hasText: statLabel }).first();
    await stat.waitFor({ timeout: 120_000 });
    const t = Number((await stat.innerText()).replace(/[^0-9.]/g, ''));
    await page.close();
    if (i >= 1) times.push(t);
  }
  record(label, times, 'self-timed by the page');
}

const named = (scope, text) =>
  `[...document.querySelectorAll('${scope} button')].find(b => b.textContent.trim() === ${JSON.stringify(text)})`;

checkLoad();
const server = await serve();
const browser = await chromium.launch();
console.log(`\nmedian of ${RUNS} (after ${WARMUP} discarded), fresh page each run\n`);

try {
  for (const n of ['2', '3', '5']) {
    await timeClick(
      browser,
      `Full ${n}-signer session + complete panel render`,
      async (p) => {
        await p.locator('#signer-count').fill(n);
        await p.locator('#panel-session button', { hasText: 'Show all steps' }).click();
      },
      named('#panel-session', 'New keys'),
    );
  }

  await timeClick(
    browser,
    'All 56 BIP-327 vectors + table render',
    null,
    `document.querySelector('#tab-vectors')`,
  );

  await timeClick(
    browser,
    'Rogue-key attack: forge, then 6 fixed-point rounds',
    async (p) => { await p.locator('#tab-rogue').click(); },
    named('#panel-rogue', 'Run the rogue-key attack'),
  );

  await timeClick(
    browser,
    'The drawable group: 126 points + aggregation + plot',
    async (p) => { await p.locator('#tab-keyagg').click(); },
    named('#panel-keyagg', 'New points on the small curve'),
  );

  for (const bits of ['30', '27', '24']) {
    await readSelfTimed(
      browser,
      `Wagner forgery, ${bits}-bit challenge`,
      (p) => p.locator('#wagner-bits').selectOption(bits),
      'Forge a signature nobody authorised',
      'Search time',
      5,
    );
  }

  await readSelfTimed(
    browser,
    'ROS forgery, full 256-bit challenge, 256 sessions',
    null,
    'Forge at full 256-bit width',
    'Time',
    5,
  );
} finally {
  await browser.close();
  server.kill();
}

console.log('\n--- Markdown ---\n');
console.log('| Operation | Time | Spread over runs |');
console.log('| --- | ---: | ---: |');
for (const r of rows) {
  console.log(`| ${r.label}${r.note ? ` *(${r.note})*` : ''} | **~${ms(r.median)} ms** | ${ms(r.min)}–${ms(r.max)} ms |`);
}
console.log(`\nmachine: ${cpus().length} cores, 1-min load ${loadavg()[0].toFixed(2)} at finish`);
