import { defineConfig, devices } from '@playwright/test';

/**
 * End-to-end suites, both run against the production build served by
 * `vite preview`, so what passes here is what ships:
 *   - a11y.spec.ts  — the WCAG 2.1 A/AA gate, run in {dark, light} x {1280, 380}.
 *     It drives every exhibit and scans after every step; see e2e/gate.ts.
 *   - flows.spec.ts — functional flows, across Chromium desktop, a mobile viewport,
 *     Firefox and WebKit.
 *
 * `npm run test:a11y` runs the axe gate plus the Chromium flows, which is what
 * `deploy.yml`'s gate step invokes — so a functional regression blocks the deploy just
 * as an accessibility one does. Firefox and WebKit run in a separate workflow.
 *
 * Port 4276 is unique to this lab across the fleet (never the Vite default 4173,
 * which every sibling lab would otherwise share).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 240_000, // flows only — a11y.spec.ts sets its own, much larger, budget
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4276/crypto-lab-musig-gate/',
  },
  /**
   * Two tiers, because the Pages deploy and cross-browser coverage have different
   * constraints:
   *
   *   - `npm run test:a11y` (what deploy.yml's verbatim gate step runs) selects only
   *     the Chromium projects, because that workflow installs only Chromium.
   *   - `.github/workflows/e2e.yml` installs all three engines and runs everything,
   *     so Firefox and WebKit regressions are still caught in CI — just not inside
   *     the file the template requires to stay byte-for-byte.
   */
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      // The theme is seeded through localStorage before the navigation (which also
      // pins down whether the anti-flash script and the bar's toggle agree on the
      // key), and the viewport is set per configuration inside the spec — so this
      // one project covers all four. `colorScheme` is the OS-level preference and
      // is left dark deliberately: this lab reads `data-theme`, not the media
      // query, so a light run here is also a run with the two disagreeing.
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
    {
      name: 'flows-desktop',
      testMatch: /flows\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'flows-mobile',
      testMatch: /flows\.spec\.ts/,
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'flows-firefox',
      testMatch: /flows\.spec\.ts/,
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'flows-webkit',
      testMatch: /flows\.spec\.ts/,
      use: { ...devices['Desktop Safari'] },
    },
  ],
  webServer: {
    // Build before serving. `preview` only serves whatever is already in
    // dist/; without the build in front, a failing build leaves the previous
    // good bundle on disk and the suite passes green against code that no
    // longer compiles — silently invalidating mutation checks.
    command: 'npm run build && npm run preview -- --port 4276 --strictPort',
    url: 'http://localhost:4276/crypto-lab-musig-gate/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
