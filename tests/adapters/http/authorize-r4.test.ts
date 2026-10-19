import { describe, it, expect } from 'vitest';
import { loadConfig } from '../../../src/config/config.js';
import { MailDeliveryError } from '../../../src/ports/mailer.js';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CSRF, FORM_HEADERS, browserHeaders, extractChallenge, startCodeLogin } from './helpers.js';

// Круг 4: переотправка при таймауте провайдера и пауза между письмами на адрес.

const DEFAULT_LIMITS = loadConfig({ PUBLIC_ISSUER_URL: 'https://auth.example' } as NodeJS.ProcessEnv).rateLimits;

function oidc(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    client_id: 'app',
    redirect_uri: 'https://app.example/cb',
    code_challenge: 'chal',
    code_challenge_method: 'S256',
    scope: 'openid',
    state: 'st1',
    csrf: TEST_CSRF,
    ...overrides,
  };
}

type App = ReturnType<typeof buildServer>;

function fromIp(ip: string): Record<string, string> {
  return { ...FORM_HEADERS, 'x-forwarded-for': ip };
}

// Другой браузер (своя csrf-cookie) с этого IP.
function fromBrowser(csrf: string, ip = '127.0.0.1'): Record<string, string> {
  return { ...browserHeaders(csrf), 'x-forwarded-for': ip };
}

function identify(app: App, email: string, headers: Record<string, string> = FORM_HEADERS) {
  const csrf = /csrf=([^;]+)/.exec(headers.cookie ?? '')?.[1] ?? TEST_CSRF;
  return app.inject({
    method: 'POST',
    url: '/authorize/identify',
    payload: new URLSearchParams({ ...oidc({ csrf }), email }).toString(),
    headers,
  });
}

function resend(app: App, challenge: string) {
  return app.inject({
    method: 'POST',
    url: '/authorize/code/request',
    payload: new URLSearchParams({ ...oidc(), challenge }).toString(),
    headers: FORM_HEADERS,
  });
}

function verify(app: App, challenge: string, code: string) {
  return app.inject({
    method: 'POST',
    url: '/authorize/code/verify',
    payload: new URLSearchParams({ ...oidc(), challenge, code }).toString(),
    headers: FORM_HEADERS,
  });
}

describe('R4-A1: переотправка без ответа провайдера', () => {
  it('таймаут → экран кода «письмо может прийти», код из этого письма принимается', async () => {
    const deps = await makeTestDeps({ codeSequence: ['111111', '222222'] });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    const send = deps.mailer.send.bind(deps.mailer);
    deps.mailer.send = async (email) => { await send(email); throw new MailDeliveryError('timeout'); };
    const res = await resend(app, challenge);
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain('Если письмо всё же придёт, введите код из него');
    expect(res.body).not.toContain('Не удалось отправить письмо');
    expect(extractChallenge(res.body)).toBe(challenge);
    expect(deps.mailer.last?.text).toContain('222222');
    expect((await verify(app, challenge, '111111')).headers['location']).toBeUndefined();
    expect((await verify(app, challenge, '222222')).statusCode).toBe(302);
    await app.close();
  });

  it('отказ провайдера → «не удалось отправить», прежний код действует', async () => {
    const deps = await makeTestDeps({ codeSequence: ['111111', '222222'] });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    deps.mailer.send = async () => { throw new MailDeliveryError('422', 'rejected'); };
    const res = await resend(app, challenge);
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain('Не удалось отправить письмо');
    expect((await verify(app, challenge, '111111')).statusCode).toBe(302);
    await app.close();
  });
});

describe('R4: пауза между новыми письмами на один адрес', () => {
  it('по умолчанию: пауза 60 с и суточный потолок 20 новых попыток, часового отказа нет', () => {
    expect(DEFAULT_LIMITS.codeRequestEmailPause).toEqual({ limit: 1, windowSeconds: 60 });
    expect(DEFAULT_LIMITS.codeRequestPerEmailDaily).toEqual({ limit: 20, windowSeconds: 86400 });
    expect(DEFAULT_LIMITS).not.toHaveProperty('codeRequestPerEmail');
  });

  it('владелец сразу после постороннего ждёт секунды, а не час, и остаётся на форме с адресом', async () => {
    const deps = await makeTestDeps({ trustProxy: 1, rateLimits: DEFAULT_LIMITS });
    const app = buildServer(deps);
    expect((await identify(app, 'owner@x.com', fromBrowser('stranger', '203.0.113.1'))).statusCode).toBe(200);
    deps.clock.advance(18);
    const paused = await identify(app, 'owner@x.com', fromIp('198.51.100.1'));
    expect(paused.statusCode).toBe(429);
    expect(paused.headers['retry-after']).toBe('42');
    expect(paused.body).toContain('через 42 с');
    expect(paused.body).toContain('value="owner@x.com"');
    expect(paused.body).toContain('Получить код');
    deps.clock.advance(42);
    expect((await identify(app, 'owner@x.com', fromIp('198.51.100.1'))).statusCode).toBe(200);
    await app.close();
  });

  it('10 писем постороннего за 10 минут не закрывают владельцу отправку на час', async () => {
    const deps = await makeTestDeps({ trustProxy: 1, rateLimits: DEFAULT_LIMITS });
    const app = buildServer(deps);
    for (let i = 0; i < 10; i++) {
      expect((await identify(app, 'owner@x.com', fromIp(`203.0.113.${i + 1}`))).statusCode).toBe(200);
      deps.clock.advance(60);
    }
    expect((await identify(app, 'owner@x.com', fromIp('198.51.100.1'))).statusCode).toBe(200);
    await app.close();
  });

  it('суточный потолок адреса держит и при ротации IP', async () => {
    const deps = await makeTestDeps({ trustProxy: 1, rateLimits: DEFAULT_LIMITS });
    const app = buildServer(deps);
    for (let i = 0; i < 20; i++) {
      expect((await identify(app, 'victim@x.com', fromIp(`203.0.113.${i + 1}`))).statusCode).toBe(200);
      deps.clock.advance(60);
    }
    const res = await identify(app, 'victim@x.com', fromIp('198.51.100.1'));
    expect(res.statusCode).toBe(429);
    expect(res.body).toMatch(/через \d+ ч/);
    expect(deps.mailer.sent).toHaveLength(20);
    await app.close();
  });

  it('отказ по паузе не тратит бюджет источника', async () => {
    const deps = await makeTestDeps({
      rateLimits: {
        codeRequestPerIp: { limit: 2, windowSeconds: 3600 },
        codeRequestEmailPause: DEFAULT_LIMITS.codeRequestEmailPause,
      },
    });
    const app = buildServer(deps);
    expect((await identify(app, 'a@x.com')).statusCode).toBe(200);
    expect((await identify(app, 'a@x.com', fromBrowser('other'))).statusCode).toBe(429);
    expect((await identify(app, 'b@x.com')).statusCode).toBe(200);
    await app.close();
  });
});
