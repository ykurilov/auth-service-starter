import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CSRF, FORM_HEADERS } from './helpers.js';

// Аудит #8: за обратным прокси req.ip обязан браться из X-Forwarded-For
// (trustProxy=число хопов), иначе все IP-лимиты схлопываются в один глобальный
// бакет. И отдельно — лимит по одному email против бомбинга с ротацией IP.

function codeReqForm(email: string): string {
  return new URLSearchParams({
    client_id: 'app',
    redirect_uri: 'https://app.example/cb',
    code_challenge: 'chal',
    code_challenge_method: 'S256',
    scope: 'openid',
    state: 'st1',
    csrf: TEST_CSRF,
    email,
  }).toString();
}

function codeReqPost(app: ReturnType<typeof buildServer>, xff: string, email: string) {
  return app.inject({
    method: 'POST',
    url: '/authorize/identify',
    payload: codeReqForm(email),
    headers: { ...FORM_HEADERS, 'x-forwarded-for': xff },
  });
}

// /authorize/identify — вход по коду, лимит codeRequest с ключом
// code-req:${ipHash}:${email}. Email фиксируем, тогда бакет различает только IP,
// и на identify виден эффект trustProxy: тот же email, но разные IP.
function identifyPost(app: ReturnType<typeof buildServer>, xff: string) {
  return app.inject({
    method: 'POST',
    url: '/authorize/identify',
    payload: codeReqForm('same@x.com'),
    headers: { ...FORM_HEADERS, 'x-forwarded-for': xff },
  });
}

describe('IP за прокси и лимит по email (аудит #8)', () => {
  it('trustProxy=1: разные X-Forwarded-For — разные ip-бакеты (лимит не схлопнут)', async () => {
    const deps = await makeTestDeps({
      trustProxy: 1,
      rateLimits: { codeRequest: { limit: 1, windowSeconds: 900 } },
    });
    const app = buildServer(deps);

    const a = await identifyPost(app, '203.0.113.1');
    const b = await identifyPost(app, '203.0.113.2');

    expect(a.statusCode).toBe(200);
    expect(b.statusCode).toBe(200); // другой IP → отдельный бакет, не 429
    await app.close();
  });

  it('trustProxy=0: X-Forwarded-For игнорируется — общий бакет (демонстрация схлопывания)', async () => {
    const deps = await makeTestDeps({
      trustProxy: 0,
      rateLimits: { codeRequest: { limit: 1, windowSeconds: 900 } },
    });
    const app = buildServer(deps);

    const a = await identifyPost(app, '203.0.113.1');
    const b = await identifyPost(app, '203.0.113.2');

    expect(a.statusCode).toBe(200);
    // Без доверия прокси req.ip одинаков (адрес сокета) → второй режется тем же
    // ip-бакетом, хотя это другой клиент. Это ровно тот баг, что чинит trustProxy.
    expect(b.statusCode).toBe(429);
    await app.close();
  });

  it('лимит по email режет бомбинг одного адреса даже с ротацией IP', async () => {
    // Широкий ip+email не мешает (высокий), но email-лимит = 2: третье письмо
    // на тот же адрес режется, хотя каждый запрос идёт с нового IP.
    const deps = await makeTestDeps({
      trustProxy: 1,
      rateLimits: {
        codeRequest: { limit: 100, windowSeconds: 900 },
        codeRequestPerEmail: { limit: 2, windowSeconds: 3600 },
      },
    });
    const app = buildServer(deps);

    const r1 = await codeReqPost(app, '203.0.113.10', 'victim@x.com');
    const r2 = await codeReqPost(app, '203.0.113.11', 'victim@x.com');
    const r3 = await codeReqPost(app, '203.0.113.12', 'victim@x.com');

    expect(r1.statusCode).toBe(200);
    expect(r2.statusCode).toBe(200);
    expect(r3.statusCode).toBe(429); // лимит по email, несмотря на новый IP
    await app.close();
  });

  it('суточный бюджет адреса держит и при ротации IP (бюджет аккаунта)', async () => {
    const deps = await makeTestDeps({
      trustProxy: 1,
      rateLimits: {
        codeRequest: { limit: 100, windowSeconds: 900 },
        codeRequestPerEmail: { limit: 100, windowSeconds: 3600 },
        codeRequestPerEmailDaily: { limit: 3, windowSeconds: 86400 },
      },
    });
    const app = buildServer(deps);
    const statuses = [];
    for (let i = 0; i < 4; i++) statuses.push((await codeReqPost(app, `198.51.100.${i}`, 'victim@x.com')).statusCode);
    expect(statuses).toEqual([200, 200, 200, 429]);
    expect(deps.mailer.sent).toHaveLength(3);
    await app.close();
  });
});
