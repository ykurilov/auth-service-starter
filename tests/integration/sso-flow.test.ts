import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CHALLENGE, TEST_CSRF, FORM_HEADERS, extractChallenge } from '../adapters/http/helpers.js';
import type { Client } from '../../src/domain/clients/client.js';

// csrf-cookie для форм входа; в confirm/logout cookie перекрывается ниже.
const FORM = FORM_HEADERS;

const APP1: Client = {
  id: 'app1',
  type: 'external',
  redirectUris: ['https://app1.example/cb'],
  allowedProviders: ['email'],
  postLogoutRedirectUris: ['https://app1.example/after-logout'],
};

const APP2: Client = {
  id: 'app2',
  type: 'external',
  redirectUris: ['https://app2.example/cb'],
  allowedProviders: ['email'],
};

function oidc(clientId: string, redirectUri: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: TEST_CHALLENGE,
    code_challenge_method: 'S256',
    scope: 'openid',
    state: 'st1',
    ...extra,
  };
}

function setCookieLines(res: { headers: Record<string, unknown> }): string[] {
  const raw = res.headers['set-cookie'];
  return Array.isArray(raw) ? raw : [String(raw ?? '')];
}

function readSetCookie(res: { headers: Record<string, unknown> }, name: string): string {
  for (const line of setCookieLines(res)) {
    const m = new RegExp(`${name}=([^;]+)`).exec(line);
    if (m && m[1] !== undefined) return m[1];
  }
  throw new Error(`set-cookie ${name} not found`);
}

function csrfFieldOf(body: string): string {
  const m = /name="csrf"\s+value="([^"]+)"/.exec(body);
  if (!m?.[1]) throw new Error('csrf-поле не найдено в HTML');
  return m[1];
}

// Сквозной SSO: вход в app1 → бесшовное согласие в app2 → switch → выход
// гасит единую SSO-сессию для всех приложений. Единый deps/app, cookie
// переносятся между запросами вручную через заголовок cookie.
describe('SSO flow (несколько приложений)', () => {
  let app: FastifyInstance;
  let sso: string;

  beforeAll(async () => {
    app = buildServer(await makeTestDeps({ clients: [APP1, APP2] }));
  });

  afterAll(async () => {
    await app.close();
  });

  it('1. вход в app1 по коду → 302 с кодом и sso-cookie', async () => {
    const identify = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: new URLSearchParams({
        ...oidc('app1', 'https://app1.example/cb'),
        email: 'new@user.com',
        csrf: TEST_CSRF,
      }).toString(),
      headers: FORM,
    });
    const challenge = extractChallenge(identify.body);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/code/verify',
      payload: new URLSearchParams({
        ...oidc('app1', 'https://app1.example/cb'),
        challenge,
        code: 'CODE55',
        csrf: TEST_CSRF,
      }).toString(),
      headers: FORM,
    });
    expect(res.statusCode).toBe(302);
    const location = new URL(res.headers['location'] as string);
    expect(location.origin + location.pathname).toBe('https://app1.example/cb');
    expect(location.searchParams.get('code')).toBeTruthy();
    sso = readSetCookie(res, 'sso');
    expect(sso).toBeTruthy();
  });

  it('2. GET /authorize для app2 с sso-cookie → экран согласия', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams(oidc('app2', 'https://app2.example/cb')).toString()}`,
      headers: { cookie: `sso=${sso}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Продолжить как');
    expect(res.body).toContain('/authorize/confirm');
    expect(setCookieLines(res).some((l) => l.includes('csrf='))).toBe(true);
  });

  it('3. POST /authorize/confirm для app2 → 302 с кодом на redirect app2', async () => {
    const getRes = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams(oidc('app2', 'https://app2.example/cb')).toString()}`,
      headers: { cookie: `sso=${sso}` },
    });
    const csrfCookie = readSetCookie(getRes, 'csrf');
    const csrfField = csrfFieldOf(getRes.body);

    const res = await app.inject({
      method: 'POST',
      url: '/authorize/confirm',
      payload: new URLSearchParams({
        ...oidc('app2', 'https://app2.example/cb'),
        csrf: csrfField,
      }).toString(),
      headers: { ...FORM, cookie: `sso=${sso}; csrf=${csrfCookie}` },
    });
    expect(res.statusCode).toBe(302);
    const location = new URL(res.headers['location'] as string);
    expect(location.origin + location.pathname).toBe('https://app2.example/cb');
    expect(location.searchParams.get('code')).toBeTruthy();
  });

  it('4. GET /authorize для app2 с prompt=login → форма входа, не согласие', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams(
        oidc('app2', 'https://app2.example/cb', { prompt: 'login' }),
      ).toString()}`,
      headers: { cookie: `sso=${sso}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('/authorize/identify');
    expect(res.body).not.toContain('/authorize/confirm');
  });

  it('5. logout app1 → 302 на post_logout_redirect_uri, sso-cookie погашена', async () => {
    const getRes = await app.inject({
      method: 'GET',
      url: `/logout?${new URLSearchParams({
        client_id: 'app1',
        post_logout_redirect_uri: 'https://app1.example/after-logout',
      }).toString()}`,
      headers: { cookie: `sso=${sso}` },
    });
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body).toContain('action="/logout"');
    const csrfCookie = readSetCookie(getRes, 'csrf');
    const csrfField = csrfFieldOf(getRes.body);

    const res = await app.inject({
      method: 'POST',
      url: '/logout',
      payload: new URLSearchParams({
        client_id: 'app1',
        post_logout_redirect_uri: 'https://app1.example/after-logout',
        csrf: csrfField,
      }).toString(),
      headers: { ...FORM, cookie: `sso=${sso}; csrf=${csrfCookie}` },
    });
    expect(res.statusCode).toBe(302);
    expect(res.headers['location']).toBe('https://app1.example/after-logout');
    const ssoClear = setCookieLines(res).find((l) => l.startsWith('sso='));
    expect(ssoClear).toBeTruthy();
    expect(/Max-Age=0|Expires=Thu, 01 Jan 1970/.test(ssoClear ?? '')).toBe(true);
  });

  it('6. GET /authorize для app2 со старой sso-cookie → форма входа (сессия отозвана)', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams(oidc('app2', 'https://app2.example/cb')).toString()}`,
      headers: { cookie: `sso=${sso}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('/authorize/identify');
    expect(res.body).not.toContain('/authorize/confirm');
  });
});
