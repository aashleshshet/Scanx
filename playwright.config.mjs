import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests-e2e',
  retries: 0,
  use: { baseURL: 'http://127.0.0.1:3100', trace: 'off' },
  webServer: {
    command: 'pnpm start --hostname 127.0.0.1 --port 3100',
    url: 'http://127.0.0.1:3100/workspace/index.html',
    reuseExistingServer: !process.env.CI,
  },
});
