import { describe, expect, it } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps } from './helpers.js';

describe('GET /', () => {
  it('отдаёт заглавную страницу вместо 404', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);

    const res = await app.inject({ method: 'GET', url: '/' });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.body).toContain('Сервис авторизации');
    expect(res.body).toContain('работает');
    expect(res.body).toContain('/assets/design-system.css');
  });
});

describe('GET /assets/design-system.css', () => {
  it('отдаёт стили дизайн-системы с кэшем', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);

    const res = await app.inject({ method: 'GET', url: '/assets/design-system.css' });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/css');
    expect(res.headers['cache-control']).toContain('max-age');
    expect(res.body).toContain(':root');
  });
});
