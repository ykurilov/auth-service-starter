import { defineConfig } from 'vite';

// Фронт на 3007, сервер Hono на 3008. Браузер видит один адрес (3007): /api
// Vite передаёт серверу, поэтому cookie входа общие для страниц и API.
// AUTH_APP_URL — адрес, который видит браузер: http://localhost:3007.
export default defineConfig({
  server: {
    port: 3007,
    strictPort: true,
    proxy: { '/api': 'http://localhost:3008' },
  },
  build: {
    rollupOptions: { input: ['index.html', 'cabinet.html'] },
  },
});
