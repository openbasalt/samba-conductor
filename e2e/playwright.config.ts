import { defineConfig, devices } from '@playwright/test';

// The suite runs on server-home in the official Playwright container
// (host network), against conductor installed on the lab's dc1.
// e2e/run-lab.sh sets the environment; see docs/usage-p1.md.
const host = 'dc1.lab.conductor.test';
const ip = process.env.E2E_DC1_IP ?? '10.93.0.10';
const spki = process.env.E2E_CERT_SPKI ?? '';

const chromiumArgs = [`--host-resolver-rules=MAP ${host} ${ip}`];
if (spki) {
  // Trust exactly conductor's certificate (lab CA is not in the browser).
  chromiumArgs.push(`--ignore-certificate-errors-spki-list=${spki}`);
}

export default defineConfig({
  testDir: './tests',
  // The tests share one lab domain and enroll 2FA in order: run serially.
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? `https://${host}:8443`,
    testIdAttribute: 'data-e2e',
    trace: 'retain-on-failure',
    launchOptions: { args: chromiumArgs },
    locale: 'en-US',
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1366, height: 900 } } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
});
