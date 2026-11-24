import { fileURLToPath, URL } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const root = fileURLToPath(new URL('..', import.meta.url));
  const env = loadEnv(mode, root, ['API_', 'SECURITY_']);
  return {
    plugins: [react()],
    cacheDir: '.vite',
    envDir: root,
    server: {
      port: 5173,
      strictPort: true,
      proxy: {
        '/api/v1/security': { target: env.SECURITY_PROXY_TARGET || 'http://127.0.0.1:8002', changeOrigin: true },
        '/api': { target: env.API_PROXY_TARGET || 'http://127.0.0.1:8000', changeOrigin: true },
      },
    },
  };
});
