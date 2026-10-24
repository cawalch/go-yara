import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './playground/tests',
  testMatch: '*.spec.mjs',
  timeout: 60000,
  expect: { timeout: 25000 },
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: { baseURL: 'http://127.0.0.1:4333', headless: false, screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
  webServer: {
    command: 'python3 playground/tests/server.py',
    url: 'http://127.0.0.1:4333/go-yara/quickstart/',
    reuseExistingServer: !process.env.CI,
  },
});
