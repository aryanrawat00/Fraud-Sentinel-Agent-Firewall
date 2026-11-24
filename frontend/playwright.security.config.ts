import { defineConfig, devices } from '@playwright/test';
export default defineConfig({
  testDir: './tests', testMatch: ['security.spec.ts', 'security-integration.spec.ts'], workers: 1,
  use: { baseURL: 'http://127.0.0.1:5176', ...devices['Desktop Chrome'] },
  webServer: { command: 'npm run dev -- --port 5176', env: { SECURITY_PROXY_TARGET: 'http://127.0.0.1:8004' }, url: 'http://127.0.0.1:5176', reuseExistingServer: false },
});
