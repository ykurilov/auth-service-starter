import { describe, it, expect, vi } from 'vitest';
import { loadConfig } from '../../../src/config/config.js';
import { MailDeliveryError } from '../../../src/ports/mailer.js';
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

  it('D2: верный код не тратит бюджет проверок IP — класс за одним IP входит целиком', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeVerifyPerIp: { limit: 2, windowSeconds: 900 } } });
    const app = buildServer(deps);
    for (const email of ['a@x.com', 'b@x.com', 'c@x.com', 'd@x.com', 'e@x.com']) {
      const challenge = await startCodeLogin(app, email);
      expect((await verify(app, challenge, 'CODE55')).statusCode).toBe(302);
    }
    // Бюджет цел: две ошибки ещё допускаются, третья упирается в лимит.
    const f = await startCodeLogin(app, 'f@x.com');
    expect((await verify(app, f, 'BAD1')).statusCode).toBe(200);
    expect((await verify(app, f, 'BAD2')).statusCode).toBe(200);
    expect((await verify(app, f, 'CODE55')).statusCode).toBe(429);
    await app.close();
  });

  it('D2: боевые лимиты по умолчанию пропускают группу из 40 человек за одним IP', async () => {
    const prod = loadConfig({ PUBLIC_ISSUER_URL: 'https://auth.example' } as NodeJS.ProcessEnv).rateLimits;
    const deps = await makeTestDeps({ rateLimits: prod });
    const app = buildServer(deps);
    const statuses: number[] = [];
    for (let i = 0; i < 40; i++) {
      const csrf = `browser-${i}`;
      const headers = browserHeaders(csrf);
      const id = await app.inject({
        method: 'POST',
        url: '/authorize/identify',
        payload: new URLSearchParams({ ...oidc({ csrf }), email: `student${i}@x.com` }).toString(),
        headers,
      });
      const challenge = extractChallenge(id.body);
      // Каждый третий сначала ошибается в коде.
      if (i % 3 === 0) expect((await verify(app, challenge, 'BAD999', headers, csrf)).statusCode).toBe(200);
      statuses.push((await verify(app, challenge, 'CODE55', headers, csrf)).statusCode);
      deps.clock.advance(10);
    }
    expect(statuses.filter((s) => s !== 302)).toEqual([]);
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

describe('R11: бюджеты отправки и исчерпанная попытка', () => {
  function resend(app: App, challenge: string) {
    return app.inject({
      method: 'POST',
      url: '/authorize/code/request',
      payload: new URLSearchParams({ ...oidc(), challenge }).toString(),
      headers: FORM_HEADERS,
    });
  }

  it('дефолтный лимит вмещает первую отправку и 3 повторные', async () => {
    const deps = await makeTestDeps({
      rateLimits: loadConfig({ PUBLIC_ISSUER_URL: 'https://auth.example' } as NodeJS.ProcessEnv).rateLimits,
    });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    for (let i = 0; i < 3; i++) {
      const res = await resend(app, challenge);
      expect(res.statusCode).toBe(200);
      expect(res.body).toContain('Отправили новый код');
    }
    expect(deps.mailer.sent.length).toBe(4);
    await app.close();
  });

  it('повторы исчерпаны → лимит отправки не списывается', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeRequest: { limit: 100, windowSeconds: 900 } } });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    for (let i = 0; i < 3; i++) await resend(app, challenge);
    const hit = vi.spyOn(deps.otpRateLimiter!, 'hit');
    const res = await resend(app, challenge);
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('начните вход заново');
    expect(hit).not.toHaveBeenCalled();
    await app.close();
  });

  it('проверки исчерпаны → лимит отправки не списывается', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    for (let i = 0; i < 5; i++) await verify(app, challenge, `BAD${i}`);
    const hit = vi.spyOn(deps.otpRateLimiter!, 'hit');
    const res = await resend(app, challenge);
    expect(res.body).toContain('начните вход заново');
    expect(hit).not.toHaveBeenCalled();
    await app.close();
  });

  it('JS-режим: проверки исчерпаны → сигнал вернуться к вводу почты (prompt=login)', async () => {
    const app = buildServer(await makeTestDeps());
    const challenge = await startCodeLogin(app, 'user@x.com');
    const replace = { ...FORM_HEADERS, 'x-auth-navigation': 'replace' };
    for (let i = 0; i < 4; i++) {
      const res = await verify(app, challenge, `BAD${i}`, replace);
      expect(res.json()).toEqual({ error: 'Неверный или просроченный код' });
    }
    const last = await verify(app, challenge, 'BAD4', replace);
    expect(last.statusCode).toBe(401);
    const body = last.json() as { error: string; restartTo: string };
    expect(body.error).toContain('попытки закончились');
    const restart = new URL(body.restartTo, 'https://auth.example');
    expect(restart.pathname).toBe('/authorize');
    expect(restart.searchParams.get('prompt')).toBe('login');
    expect(restart.searchParams.get('client_id')).toBe('app');
    expect(restart.searchParams.get('state')).toBe('st1');
    await app.close();
  });
});

describe('R15: письмо не ушло', () => {
  it('сбой отправки при запросе кода → 503, экран кода с попыткой (T21)', async () => {
    const deps = await makeTestDeps();
    deps.mailer.send = async () => { throw new MailDeliveryError('timeout'); };
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: new URLSearchParams({ ...oidc(), email: 'user@x.com' }).toString(),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain('Не удалось подтвердить отправку письма');
    expect(res.body).toContain('name="code"');
    await app.close();
  });

  it('отказ провайдера при повторе кода → 503, экран кода с ошибкой', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    deps.mailer.send = async () => { throw new MailDeliveryError('422', 'rejected'); };
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/code/request',
      payload: new URLSearchParams({ ...oidc(), challenge }).toString(),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain('Не удалось отправить письмо');
    expect(extractChallenge(res.body)).toBe(challenge);
    await app.close();
  });
});

describe('R19: повторный вход гасит прежнюю SSO-сессию', () => {
  function ssoOf(res: { headers: Record<string, unknown> }): string {
    const raw = res.headers['set-cookie'];
    const line = (Array.isArray(raw) ? raw : [String(raw ?? '')]).find((l) => l.startsWith('sso='));
    if (!line) throw new Error('нет sso-cookie');
    return /^sso=([^;]+)/.exec(line)![1]!;
  }

  it('вход по коду с прежней sso-cookie → прежняя сессия отозвана', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const first = ssoOf(await verify(app, await startCodeLogin(app, 'a@x.com'), 'CODE55'));
    const withOld = { ...FORM_HEADERS, cookie: `${FORM_HEADERS.cookie}; sso=${first}` };
    const second = ssoOf(await verify(app, await startCodeLogin(app, 'b@x.com', {}, withOld), 'CODE55', withOld));
    expect(second).not.toBe(first);
    expect(await deps.sso.resolve(first)).toBeNull();
    expect(await deps.sso.resolve(second)).not.toBeNull();
    await app.close();
  });
});
