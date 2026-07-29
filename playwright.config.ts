import { defineConfig, devices } from '@playwright/test';

/**
 * End-to-end suites, both run against the production build served by
 * `vite preview`, so what passes here is what ships:
 *   - a11y.spec.ts  — the axe WCAG 2.1 A/AA gate, both themes.
 *   - flows.spec.ts — functional flows, on a desktop and a mobile viewport.
 *
 * `npm run test:a11y` runs BOTH, which is what `deploy.yml`'s gate step invokes —
 * so a functional regression blocks the deploy just as an accessibility one does.
 *
 * Port 4276 is unique to this lab across the fleet (never the Vite default 4173,
 * which every sibling lab would otherwise share).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 120_000, // the axe driver walks every exhibit + disclosure before scanning
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4276/crypto-lab-musig-gate/',
  },
  // Chromium only, on purpose: deploy.yml installs just Chromium and runs the whole
  // suite in one gate step, so a Firefox or WebKit project here would break CI
  // rather than strengthen it.
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      // Scan the real dark default; the bar's toggle deterministically reaches light.
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
  ],
  webServer: {
    command: 'npm run preview -- --port 4276 --strictPort',
    url: 'http://localhost:4276/crypto-lab-musig-gate/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
