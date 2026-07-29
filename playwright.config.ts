import { defineConfig, devices } from '@playwright/test';

/**
 * The a11y gate runs against the production build served by `vite preview`, so
 * what passes here is what ships.
 *
 * Port 4276 is unique to this lab across the fleet (never the Vite default 4173,
 * which every sibling lab would otherwise share).
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 120_000, // the axe driver walks every exhibit + disclosure before scanning
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    ...devices['Desktop Chrome'],
    baseURL: 'http://localhost:4276/crypto-lab-musig-gate/',
    // Scan the real dark default; the shared bar's toggle deterministically reaches light.
    colorScheme: 'dark',
  },
  webServer: {
    command: 'npm run preview -- --port 4276 --strictPort',
    url: 'http://localhost:4276/crypto-lab-musig-gate/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
