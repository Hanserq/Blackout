// Playwright test configuration for Blackout
const { defineConfig } = require('playwright/test');

module.exports = defineConfig({
  testDir: './tests',
  timeout: 120000,
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:8123',
    acceptDownloads: true,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'python3 -m http.server 8123 --bind 127.0.0.1',
    url: 'http://127.0.0.1:8123',
    reuseExistingServer: true,
    timeout: 15000,
  },
  projects: [
    { name: 'chrome', use: { browserName: 'chromium', channel: 'chrome' } },
  ],
});
