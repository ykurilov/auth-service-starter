import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps } from './helpers.js';

describe('buildServer', () => {
  it('отвечает 200 на GET /live', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({ method: 'GET', url: '/live' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
    await app.close();
  });

  it('на всех ответах — заголовки против clickjacking и MIME-sniffing', async () => {
    const app = buildServer(await makeTestDeps());
    // Страница входа: именно её нельзя встроить в чужой iframe.
    const page = await app.inject({
      method: 'GET',
      url: '/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_challenge=chal&code_challenge_method=S256&scope=openid',
    });
    expect(page.headers['x-frame-options']).toBe('DENY');
    expect(page.headers['content-security-policy']).toBe("frame-ancestors 'none'");
    expect(page.headers['x-content-type-options']).toBe('nosniff');
    // И на JSON-эндпоинтах тоже (защита в глубину, ничего не ломает).
    const live = await app.inject({ method: 'GET', url: '/live' });
    expect(live.headers['x-frame-options']).toBe('DENY');
    await app.close();
  });
});
