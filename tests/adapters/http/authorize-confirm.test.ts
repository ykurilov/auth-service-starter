import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CSRF, FORM_HEADERS, extractChallenge } from './helpers.js';

function oidc(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    client_id: 'app',
    redirect_uri: 'https://app.example/cb',
    code_challenge: 'chal',
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

    const res = await app.inject({
      method: 'POST',
      url: '/authorize/confirm',
      payload: new URLSearchParams({ ...oidc(), csrf: csrfField ?? '' }).toString(),
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
});
