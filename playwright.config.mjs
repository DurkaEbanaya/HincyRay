import os from 'node:os';
import path from 'node:path';
import { defineConfig, devices } from '@playwright/test';

const port = 4173;

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 15_000,
  expect: { timeout: 5_000 },
  outputDir: path.join(os.tmpdir(), 'hincyray-playwright-results'),
  reporter: 'line',
  use: {
    ...devices['Desktop Chrome'],
    baseURL: `http://127.0.0.1:${port}`,
    colorScheme: 'light',
    locale: 'ru-RU',
    timezoneId: 'UTC',
    reducedMotion: 'reduce',
    screenshot: 'off',
    trace: 'off',
    video: 'off',
  },
  webServer: {
    command: 'node tests/browser/fixture-server.mjs',
    url: `http://127.0.0.1:${port}/__fixture/health`,
    reuseExistingServer: false,
    timeout: 10_000,
    env: { PLAYWRIGHT_FIXTURE_PORT: String(port) },
  },
});
