import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CSRF, FORM_HEADERS, extractChallenge } from './helpers.js';

function oidc(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    client_id: 'app',
    redirect_uri: 'https://app.example/cb',
    code_challenge: 'chalchalchalchalchalchalchalchalchalchalchal',
    code_challenge_method: 'S256',
    scope: 'openid',
    state: 'st1',
    ...overrides,
  };
}

function getCookie(res: { headers: Record<string, unknown> }, name: string): string {
  const raw = res.headers['set-cookie'];
  const arr = Array.isArray(raw) ? raw : [String(raw ?? '')];
  for (const line of arr) {
    const m = new RegExp(`${name}=([^;]+)`).exec(line);
    if (m && m[1] !== undefined) return m[1];
  }
  throw new Error(`cookie ${name} not found`);
}

// Реальный вход по коду → возвращает sso-cookie. identify (отправка кода) →
// code/verify (обмен): именно на ответе verify выставляется sso-cookie.
async function loginAndGetSso(app: Awaited<ReturnType<typeof buildServer>>): Promise<string> {
  const identify = await app.inject({
    method: 'POST',
    url: '/authorize/identify',
    payload: new URLSearchParams({ ...oidc(), email: 'user@x.com', csrf: TEST_CSRF }).toString(),
    headers: FORM_HEADERS,
  });
  const challenge = extractChallenge(identify.body);
  const res = await app.inject({
    method: 'POST',
    url: '/authorize/code/verify',
    payload: new URLSearchParams({ ...oidc(), challenge, code: 'CODE55', csrf: TEST_CSRF }).toString(),
    headers: FORM_HEADERS,
  });
  return getCookie(res, 'sso');
}

function expectedUserOf(body: string): string {
  const m = /name="expected_user" value="([^"]+)"/.exec(body);
  if (!m) throw new Error('на странице согласия нет expected_user');
  return m[1]!;
}

describe('POST /authorize/confirm', () => {
  it('happy: валидный csrf + живая SSO → 302 с кодом', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const sso = await loginAndGetSso(app);

    // GET согласия: забираем csrf cookie и значение поля csrf из HTML.
    const getRes = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams(oidc()).toString()}`,
      headers: { cookie: `sso=${sso}` },
    });
    const csrfCookie = getCookie(getRes, 'csrf');
    const fieldMatch = /name="csrf" value="([^"]+)"/.exec(getRes.body);
    const csrfField = fieldMatch?.[1];
    expect(csrfField).toBeTruthy();

    const expectedUser = expectedUserOf(getRes.body);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/confirm',
      payload: new URLSearchParams({ ...oidc(), csrf: csrfField ?? '', expected_user: expectedUser }).toString(),
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: `sso=${sso}; csrf=${csrfCookie}`,
      },
    });
    expect(res.statusCode).toBe(302);
    const location = res.headers['location'] as string;
    expect(location).toContain('code=');
    expect(location).toContain('state=st1');
    await app.close();
  });

  it('неверный csrf → 400 без редиректа', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const sso = await loginAndGetSso(app);

    const res = await app.inject({
      method: 'POST',
      url: '/authorize/confirm',
      payload: new URLSearchParams({ ...oidc(), csrf: 'wrong' }).toString(),
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: `sso=${sso}; csrf=realcookievalue`,
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.headers['location']).toBeUndefined();
    await app.close();
  });

  it('без SSO-cookie → не 302 с кодом', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/confirm',
      payload: new URLSearchParams({ ...oidc(), csrf: 'tok' }).toString(),
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: 'csrf=tok',
      },
    });
    expect(res.statusCode).not.toBe(302);
    await app.close();
  });

  it('SSO через запрещённый провайдер → форма входа вместо unauthorized_client', async () => {
    const deps = await makeTestDeps();
    const { rawToken } = await deps.sso.start('user-1', {
      provider: 'google',
      email: 'user@x.com',
      emailVerified: true,
    });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/confirm',
      payload: new URLSearchParams({ ...oidc(), csrf: 'tok' }).toString(),
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: `sso=${rawToken}; csrf=tok`,
      },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('/authorize/identify');
    expect(res.headers['location']).toBeUndefined();
    await app.close();
  });

  it('R10: страница согласия называет приложение (origin redirect_uri) и несёт ожидаемого пользователя', async () => {
    const deps = await makeTestDeps();
    const { rawToken } = await deps.sso.start('user-A', { provider: 'email', email: 'a@x.com', emailVerified: true });
    const app = buildServer(deps);
    const page = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams(oidc()).toString()}`,
      headers: { cookie: `sso=${rawToken}` },
    });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain('https://app.example');
    expect(expectedUserOf(page.body)).toBe('user-A');
    await app.close();
  });

  it('R10: в соседней вкладке вошли другим аккаунтом → назад на /authorize, кода нет', async () => {
    const deps = await makeTestDeps();
    const a = await deps.sso.start('user-A', { provider: 'email', email: 'a@x.com', emailVerified: true });
    const app = buildServer(deps);
    const page = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams(oidc()).toString()}`,
      headers: { cookie: `sso=${a.rawToken}; csrf=tok` },
    });
    const expectedUser = expectedUserOf(page.body);
    const b = await deps.sso.start('user-B', { provider: 'email', email: 'b@x.com', emailVerified: true });
    for (const payload of [
      { ...oidc(), csrf: 'tok', expected_user: expectedUser },
      { ...oidc(), csrf: 'tok' },
    ]) {
      const res = await app.inject({
        method: 'POST',
        url: '/authorize/confirm',
        payload: new URLSearchParams(payload).toString(),
        headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sso=${b.rawToken}; csrf=tok` },
      });
      expect(res.statusCode).toBe(303);
      const location = res.headers['location'] as string;
      expect(location.startsWith('/authorize?')).toBe(true);
      expect(location).not.toContain('code=');
      const back = new URL(location, 'https://auth.example').searchParams;
      expect(back.get('client_id')).toBe('app');
      expect(back.get('redirect_uri')).toBe('https://app.example/cb');
      expect(back.get('state')).toBe('st1');
    }
    await app.close();
  });
});
