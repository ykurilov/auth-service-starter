import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CSRF, FORM_HEADERS, browserHeaders } from './helpers.js';

// Аудит #8: за обратным прокси req.ip обязан браться из X-Forwarded-For
// (trustProxy=число хопов), иначе все IP-лимиты схлопываются в один глобальный
// бакет. И отдельно — лимит по одному email против бомбинга с ротацией IP.

function codeReqForm(email: string, csrf = TEST_CSRF): string {
  return new URLSearchParams({
    client_id: 'app',
    redirect_uri: 'https://app.example/cb',
    code_challenge: 'chalchalchalchalchalchalchalchalchalchalchal',
    code_challenge_method: 'S256',
    scope: 'openid',
    state: 'st1',
    csrf,
    email,
  }).toString();
}

// csrf — браузер: у каждого своя csrf-cookie.
function codeReqPost(app: ReturnType<typeof buildServer>, xff: string, email: string, csrf = TEST_CSRF) {
  return app.inject({
    method: 'POST',
    url: '/authorize/identify',
    payload: codeReqForm(email, csrf),
    headers: { ...browserHeaders(csrf), 'x-forwarded-for': xff },
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

  it('пауза по адресу режет бомбинг одного адреса даже с ротацией IP', async () => {
    // Широкий ip+email не мешает (высокий), а пауза адреса пропускает одно
    // письмо в минуту, хотя каждый запрос идёт с нового IP.
    const deps = await makeTestDeps({
      trustProxy: 1,
      rateLimits: {
        codeRequest: { limit: 100, windowSeconds: 900 },
        codeRequestEmailPause: { limit: 1, windowSeconds: 60 },
      },
    });
    const app = buildServer(deps);

    const r1 = await codeReqPost(app, '203.0.113.10', 'victim@x.com', 'browser-1');
    const r2 = await codeReqPost(app, '203.0.113.11', 'victim@x.com', 'browser-2');
    // Тот же браузер возвращается к своей попытке, но нового письма не получает.
    const r2same = await codeReqPost(app, '203.0.113.13', 'victim@x.com', 'browser-1');
    deps.clock.advance(60);
    const r3 = await codeReqPost(app, '203.0.113.12', 'victim@x.com', 'browser-2');

    expect(r1.statusCode).toBe(200);
    expect(r2.statusCode).toBe(429); // пауза адреса, несмотря на новый IP
    expect(r2same.statusCode).toBe(200);
    expect(r3.statusCode).toBe(200);
    expect(deps.mailer.sent).toHaveLength(2);
    await app.close();
  });

  it('суточный бюджет адреса держит и при ротации IP (бюджет аккаунта)', async () => {
    const deps = await makeTestDeps({
      trustProxy: 1,
      rateLimits: {
        codeRequest: { limit: 100, windowSeconds: 900 },
        codeRequestPerEmailDaily: { limit: 3, windowSeconds: 86400 },
      },
    });
    const app = buildServer(deps);
    const statuses = [];
    for (let i = 0; i < 4; i++) {
      statuses.push((await codeReqPost(app, `198.51.100.${i}`, 'victim@x.com')).statusCode);
      deps.clock.advance(60);
    }
    expect(statuses).toEqual([200, 200, 200, 429]);
    expect(deps.mailer.sent).toHaveLength(3);
    await app.close();
  });
});
