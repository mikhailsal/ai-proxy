import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './tests-e2e',
  timeout: 30_000,
  use: {
    baseURL: process.env.UI_BASE_URL || 'http://localhost:5173',
    ignoreHTTPSErrors: true,
    trace: 'on-first-retry',
  },
  webServer: process.env.UI_NO_WEBSERVER ? undefined : {
    command: 'npm run dev -- --host --port 5173',
    port: 5173,
    reuseExistingServer: true,
    timeout: 60_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})


