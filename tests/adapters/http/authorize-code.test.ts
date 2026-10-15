import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import {
  makeTestDeps,
  TEST_CSRF,
  FORM_HEADERS,
  browserHeaders,
  extractChallenge,
  startCodeLogin,
} from './helpers.js';

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

function verify(
  app: App,
  challenge: string,
  code: string,
  headers: Record<string, string> = FORM_HEADERS,
  csrf = TEST_CSRF,
) {
  return app.inject({
    method: 'POST',
    url: '/authorize/code/verify',
    payload: new URLSearchParams({ ...oidc({ csrf }), challenge, code }).toString(),
    headers,
  });
}

describe('POST вход по коду на почту', () => {
  it('identify → 200 с формой ввода кода, handle попытки и письмом', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: new URLSearchParams({ ...oidc(), email: 'user@x.com' }).toString(),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toContain('name="code"');
    expect(extractChallenge(res.body).length).toBeGreaterThanOrEqual(43);
    // Адрес в формах больше не передаётся — попытка знает его сама.
    expect(res.body).not.toContain('name="email" value=');
    expect(res.body).toContain('window.location.replace(data.redirectTo)');
    expect(deps.mailer.last?.text).toContain('CODE55');
    await app.close();
  });

  it('verify без JavaScript сохраняет обычный 302 fallback', async () => {
    const app = buildServer(await makeTestDeps());
    const challenge = await startCodeLogin(app, 'user@x.com');
    const res = await verify(app, challenge, 'CODE55');
    expect(res.statusCode).toBe(302);
    expect(res.headers['location'] as string).toContain('code=');
    await app.close();
  });

  it('verify с верным кодом → адрес для replace-навигации с кодом авторизации', async () => {
    const app = buildServer(await makeTestDeps());
    const challenge = await startCodeLogin(app, 'user@x.com');
    const res = await verify(app, challenge, 'CODE55', { ...FORM_HEADERS, 'x-auth-navigation': 'replace' });
    expect(res.statusCode).toBe(200);
    expect(res.json<{ redirectTo: string }>().redirectTo).toContain('code=');
    const setCookie = res.headers['set-cookie'];
    const cookieStr = Array.isArray(setCookie) ? setCookie.join('\n') : String(setCookie ?? '');
    expect(cookieStr).toMatch(/sso=[^;]+/);
    await app.close();
  });

  it('verify с неверным кодом → 200 с ошибкой, попытка сохраняется', async () => {
    const app = buildServer(await makeTestDeps());
    const challenge = await startCodeLogin(app, 'user@x.com');
    const res = await verify(app, challenge, 'WRONG');
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Неверный или просроченный код');
    expect(extractChallenge(res.body)).toBe(challenge);
    expect((await verify(app, challenge, 'CODE55')).statusCode).toBe(302);
    await app.close();
  });

  it('verify с неверным кодом через replace-навигацию возвращает ошибку без HTML', async () => {
    const app = buildServer(await makeTestDeps());
    const challenge = await startCodeLogin(app, 'user@x.com');
    const res = await verify(app, challenge, 'WRONG', { ...FORM_HEADERS, 'x-auth-navigation': 'replace' });
    expect(res.statusCode).toBe(401);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.json()).toEqual({ error: 'Неверный или просроченный код' });
    await app.close();
  });

  it('код одноразовый: повторное предъявление после входа отклоняется', async () => {
    const app = buildServer(await makeTestDeps());
    const challenge = await startCodeLogin(app, 'user@x.com');
    expect((await verify(app, challenge, 'CODE55')).statusCode).toBe(302);
    const again = await verify(app, challenge, 'CODE55');
    expect(again.statusCode).toBe(200);
    expect(again.body).toContain('запросите новый код');
    await app.close();
  });

  it('лимит попытки: после 5 неверных даже верный код не принимается', async () => {
    const app = buildServer(await makeTestDeps());
    const challenge = await startCodeLogin(app, 'user@x.com');
    for (let i = 0; i < 5; i++) expect((await verify(app, challenge, `BAD${i}`)).statusCode).toBe(200);
    const res = await verify(app, challenge, 'CODE55');
    expect(res.statusCode).toBe(200);
    expect(res.headers['location']).toBeUndefined();
    expect(res.body).toContain('попытки закончились');
    await app.close();
  });

  it('параллельные проверки не превышают лимит попытки (атомарный счётчик)', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    const results = await Promise.all(
      Array.from({ length: 12 }, (_, i) => verify(app, challenge, `BAD${i}`)),
    );
    expect(results.every((r) => r.statusCode === 200)).toBe(true);
    // Все 5 проверок израсходованы, верный код уже не проходит.
    expect((await verify(app, challenge, 'CODE55')).headers['location']).toBeUndefined();
    await app.close();
  });

  it('F11: ошибки постороннего (своя попытка на тот же адрес) не трогают попытку владельца', async () => {
    const app = buildServer(await makeTestDeps());
    const owner = await startCodeLogin(app, 'victim@x.com');
    const attackerHeaders = browserHeaders('attacker-csrf');
    const attacker = await startCodeLogin(
      app,
      'victim@x.com',
      { csrf: 'attacker-csrf' },
      attackerHeaders,
    );
    for (let i = 0; i < 6; i++) await verify(app, attacker, `BAD${i}`, attackerHeaders, 'attacker-csrf');
    const res = await verify(app, owner, 'CODE55');
    expect(res.statusCode).toBe(302);
    expect(res.headers['location'] as string).toContain('code=');
    await app.close();
  });

  it('handle владельца из чужого браузера не работает и не тратит его попытки', async () => {
    const app = buildServer(await makeTestDeps());
    const owner = await startCodeLogin(app, 'victim@x.com');
    const other = browserHeaders('other-csrf');
    for (let i = 0; i < 6; i++) {
      const r = await verify(app, owner, i === 5 ? 'CODE55' : `BAD${i}`, other, 'other-csrf');
      expect(r.headers['location']).toBeUndefined();
    }
    expect((await verify(app, owner, 'CODE55')).statusCode).toBe(302);
    await app.close();
  });

  it('F09: переотправка атомарно заменяет код — старый перестаёт действовать', async () => {
    const deps = await makeTestDeps({ codeSequence: ['111111', '222222'] });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    const resend = await app.inject({
      method: 'POST',
      url: '/authorize/code/request',
      payload: new URLSearchParams({ ...oidc(), challenge }).toString(),
      headers: FORM_HEADERS,
    });
    expect(resend.statusCode).toBe(200);
    expect(extractChallenge(resend.body)).toBe(challenge);
    expect(deps.mailer.last?.text).toContain('222222');
    expect((await verify(app, challenge, '111111')).headers['location']).toBeUndefined();
    expect((await verify(app, challenge, '222222')).statusCode).toBe(302);
    await app.close();
  });

  it('переотправка не обнуляет счётчик проверок попытки', async () => {
    const deps = await makeTestDeps({ codeSequence: ['111111', '222222'] });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    for (let i = 0; i < 5; i++) await verify(app, challenge, `BAD${i}`);
    const resend = await app.inject({
      method: 'POST',
      url: '/authorize/code/request',
      payload: new URLSearchParams({ ...oidc(), challenge }).toString(),
      headers: FORM_HEADERS,
    });
    expect(resend.statusCode).toBe(200);
    expect(resend.body).toContain('начните вход заново');
    expect(deps.mailer.sent.length).toBe(1);
    await app.close();
  });

  it.each([
    'boss@x.ru <attacker@evil.com>',
    'a@b.com,c@d.com',
    'a b@c.com',
    '"quoted"@x.com',
    'user@localhost',
    'user@1.2.3.4',
  ])('строгая проверка адреса до почты: %s → 400, письмо не уходит', async (email) => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: new URLSearchParams({ ...oidc(), email }).toString(),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(400);
    expect(res.body).toContain('Проверьте адрес почты');
    expect(deps.mailer.sent.length).toBe(0);
    await app.close();
  });

  it('клиент без email в allowedProviders → unauthorized_client, письмо не уходит', async () => {
    const deps = await makeTestDeps({
      clients: [{ id: 'app', type: 'internal', redirectUris: ['https://app.example/cb'], allowedProviders: ['google'] }],
    });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: new URLSearchParams({ ...oidc(), email: 'user@x.com' }).toString(),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(302);
    expect(res.headers['location'] as string).toContain('error=unauthorized_client');
    expect(deps.mailer.sent.length).toBe(0);
    await app.close();
  });

  it('F10: общий бюджет проверок одного IP на все попытки и адреса', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeVerifyPerIp: { limit: 3, windowSeconds: 900 } } });
    const app = buildServer(deps);
    const a = await startCodeLogin(app, 'a@x.com');
    const b = await startCodeLogin(app, 'b@x.com');
    expect((await verify(app, a, 'BAD1')).statusCode).toBe(200);
    expect((await verify(app, b, 'BAD2')).statusCode).toBe(200);
    expect((await verify(app, a, 'BAD3')).statusCode).toBe(200);
    expect((await verify(app, b, 'CODE55')).statusCode).toBe(429);
    await app.close();
  });

  it('F10: общий бюджет отправок одного IP на все адреса', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeRequestPerIp: { limit: 2, windowSeconds: 3600 } } });
    const app = buildServer(deps);
    await startCodeLogin(app, 'a@x.com');
    await startCodeLogin(app, 'b@x.com');
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: new URLSearchParams({ ...oidc(), email: 'c@x.com' }).toString(),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(429);
    expect(deps.mailer.sent.length).toBe(2);
    await app.close();
  });
});
