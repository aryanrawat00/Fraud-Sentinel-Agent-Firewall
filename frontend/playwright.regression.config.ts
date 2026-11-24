import { defineConfig, devices } from '@playwright/test';
import path from 'node:path';
const root = path.resolve('..');
const python = path.resolve(root, '../Fraud-Sentinel/.venv/Scripts/python.exe');
export default defineConfig({
  testDir: './tests', workers: 1, reporter:'list',
  use: { ...devices['Desktop Chrome'] },
  projects: [
    {name:'foundation-isolated',testMatch:'foundation.spec.ts',use:{baseURL:'http://127.0.0.1:5177'}},
    {name:'investigations-isolated',testMatch:'investigation.spec.ts',use:{baseURL:'http://127.0.0.1:5178'}},
  ],
  webServer: [
    {command:`"${python}" -B -m scripts.run_integration_ui_fixture`,cwd:root,env:{PYTHONPATH:path.join(root,'backend')},url:'http://127.0.0.1:8005/health',reuseExistingServer:false},
    {command:`"${python}" -B -m scripts.run_integration_ui_fixture --investigations`,cwd:root,env:{PYTHONPATH:path.join(root,'backend')},url:'http://127.0.0.1:8006/health',reuseExistingServer:false},
    {command:'npm run dev -- --port 5177',env:{API_PROXY_TARGET:'http://127.0.0.1:8005'},url:'http://127.0.0.1:5177',reuseExistingServer:false},
    {command:'npm run dev -- --port 5178',env:{API_PROXY_TARGET:'http://127.0.0.1:8006'},url:'http://127.0.0.1:5178',reuseExistingServer:false},
  ],
});
