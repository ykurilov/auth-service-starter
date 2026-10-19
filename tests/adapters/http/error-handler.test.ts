import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { buildServer } from '../../../src/adapters/http/server.js';
import { createLogger } from '../../../src/logging/logger.js';
import { makeTestDeps, authorizeForm, FORM_HEADERS, TEST_CSRF, browserHeaders } from './helpers.js';

// Журнал в память: уровни записей видны тесту.
function recordingLogger() {
  const levels: number[] = [];
  const logger = pino({ level: 'info' }, { write: (line: string) => { levels.push(JSON.parse(line).level); } });
  return { logger, errors: () => levels.filter((l) => l >= 50).length };
}

describe('T17: ошибки разбора тела запроса', () => {
  const cases = [
    { name: 'битый JSON → 400', headers: { 'content-type': 'application/json' }, payload: '{bad', status: 400 },
    { name: 'пустой JSON → 400', headers: { 'content-type': 'application/json' }, payload: '', status: 400 },
    { name: 'неподдерживаемый тип → 415', headers: { 'content-type': 'multipart/form-data; boundary=x' },
      payload: '--x--', status: 415 },
    { name: 'тело больше лимита → 413', headers: { 'content-type': 'application/json' },
      payload: JSON.stringify({ grant_type: 'x'.repeat(1_100_000) }), status: 413 },
  ];

  for (const c of cases) {
    it(`JSON-эндпоинт: ${c.name}, без записи error`, async () => {
      const deps = await makeTestDeps();
      const log = recordingLogger();
      deps.logger = log.logger;
      const app = buildServer(deps);
      const res = await app.inject({ method: 'POST', url: '/oauth/token', headers: c.headers, payload: c.payload });
      expect(res.statusCode).toBe(c.status);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.json().error).toBe('invalid_request');
      expect(log.errors()).toBe(0);
      await app.close();
    });
  }

  it('P3-1: код ошибки разбора виден в журнале со скрытием полей', async () => {
    const deps = await makeTestDeps();
    const lines: string[] = [];
    deps.logger = createLogger('info', { write: (line: string) => { lines.push(line); } });
    const app = buildServer(deps);
    await app.inject({
      method: 'POST', url: '/oauth/token', headers: { 'content-type': 'multipart/form-data; boundary=x' }, payload: '--x--',
    });
    expect(lines.join('')).toContain('"errorCode":"FST_ERR_CTP_INVALID_MEDIA_TYPE"');
    await app.close();
  });

  it('браузерный маршрут: битый JSON на /authorize/identify → HTML-страница 400, без записи error', async () => {
    const deps = await makeTestDeps();
    const log = recordingLogger();
    deps.logger = log.logger;
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST', url: '/authorize/identify',
      headers: { 'content-type': 'application/json', cookie: `csrf=${TEST_CSRF}` }, payload: '{bad',
    });
    expect(res.statusCode).toBe(400);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(log.errors()).toBe(0);
    await app.close();
  });
});

describe('T17: сбой на браузерных маршрутах', () => {
  it('сбой хранилища на POST /authorize/identify → HTML-страница 500, ошибка в журнале', async () => {
    const deps = await makeTestDeps();
    const log = recordingLogger();
    deps.logger = log.logger;
    deps.codeProvider.start = async () => { throw new Error('db down'); };
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST', url: '/authorize/identify', payload: authorizeForm({ email: 'u@x.com' }), headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(500);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).not.toContain('db down');
    expect(log.errors()).toBe(1);
    await app.close();
  });

  it('сбой на POST /logout → HTML-страница 500', async () => {
    const deps = await makeTestDeps();
    deps.clients.findClient = async () => { throw new Error('db down'); };
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST', url: '/logout',
      payload: new URLSearchParams({ client_id: 'app', csrf: TEST_CSRF }).toString(),
      headers: browserHeaders(TEST_CSRF),
    });
    expect(res.statusCode).toBe(500);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    await app.close();
  });

  it('сбой на JSON-эндпоинте → по-прежнему JSON 500 server_error', async () => {
    const deps = await makeTestDeps();
    deps.rateLimiter.hit = async () => { throw new Error('redis down'); };
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST', url: '/oauth/token', payload: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: 'x' }).toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({ error: 'server_error' });
    await app.close();
  });
});
