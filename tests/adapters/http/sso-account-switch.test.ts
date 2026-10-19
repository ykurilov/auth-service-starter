import { describe, it, expect } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../../src/adapters/http/server.js';
import type { Client } from '../../../src/domain/clients/client.js';
import { makeTestDeps, extractChallenge, TEST_CHALLENGE, TEST_CSRF, TEST_VERIFIER } from './helpers.js';

// T12: сессии приложений привязаны к цепочке SSO-сессий браузера. Смена
// аккаунта в одном приложении гасит прежний аккаунт во всех приложениях этого
// браузера (но не на других устройствах); выход гасит всю цепочку браузера.
// T04: выход повторяем после частичного сбоя.
const app1: Client = { id: 'app1', type: 'internal', redirectUris: ['https://app1.example/cb'], allowedProviders: ['email'] };
const app2: Client = { id: 'app2', type: 'internal', redirectUris: ['https://app2.example/cb'], allowedProviders: ['email'] };

function oidc(c: Client, extra: Record<string, string> = {}): Record<string, string> {
  return { client_id: c.id, redirect_uri: c.redirectUris[0]!, code_challenge: TEST_CHALLENGE,
    code_challenge_method: 'S256', scope: 'openid email', state: 'st', ...extra };
}

function cookieValue(res: { headers: Record<string, unknown> }, name: string): string | undefined {
  const raw = res.headers['set-cookie'];
  const lines = Array.isArray(raw) ? raw : raw ? [String(raw)] : [];
  for (const line of lines) {
    const m = new RegExp(`^${name}=([^;]*)`).exec(line);
    if (m) return m[1];
  }
  return undefined;
}

// Один браузер: своя sso-cookie, которую обновляют ответы сервиса.
function browser(app: FastifyInstance) {
  let sso: string | undefined;
  const headers = () => ({ 'content-type': 'application/x-www-form-urlencoded',
    cookie: `csrf=${TEST_CSRF}${sso ? `; sso=${sso}` : ''}` });
  const remember = (res: { headers: Record<string, unknown> }) => {
    const next = cookieValue(res, 'sso');
    if (next !== undefined) sso = next || undefined;
  };
  const exchange = async (c: Client, location: string) => {
    const code = new URL(location).searchParams.get('code');
    if (!code) throw new Error(`нет кода в ${location}`);
    const res = await app.inject({ method: 'POST', url: '/oauth/token', payload: { grant_type: 'authorization_code',
      code, client_id: c.id, redirect_uri: c.redirectUris[0]!, code_verifier: TEST_VERIFIER } });
    expect(res.statusCode).toBe(200);
    return res.json().refresh_token as string;
  };
  return {
    get sso() { return sso; },
    // Вход по коду из письма (в том числе смена аккаунта: prompt=login при живой SSO).
    async login(c: Client, email: string): Promise<string> {
      const identify = await app.inject({ method: 'POST', url: '/authorize/identify', headers: headers(),
        payload: new URLSearchParams({ ...oidc(c), email, csrf: TEST_CSRF }).toString() });
      const challenge = extractChallenge(identify.body);
      const verify = await app.inject({ method: 'POST', url: '/authorize/code/verify', headers: headers(),
        payload: new URLSearchParams({ ...oidc(c), challenge, code: 'CODE55', csrf: TEST_CSRF }).toString() });
      remember(verify);
      return exchange(c, String(verify.headers.location));
    },
    // Тихий вход через SSO-сессию браузера.
    async silent(c: Client): Promise<string> {
      const res = await app.inject({ method: 'GET', headers: headers(),
        url: `/authorize?${new URLSearchParams(oidc(c, { prompt: 'none', response_type: 'code' })).toString()}` });
      remember(res);
      return exchange(c, String(res.headers.location));
    },
    async logout(c: Client) {
      const res = await app.inject({ method: 'POST', url: '/logout', headers: headers(),
        payload: new URLSearchParams({ client_id: c.id, csrf: TEST_CSRF }).toString() });
      remember(res);
      return res;
    },
  };
}

async function refreshStatus(app: FastifyInstance, refreshToken: string): Promise<number> {
  const res = await app.inject({ method: 'POST', url: '/oauth/token',
    payload: { grant_type: 'refresh_token', refresh_token: refreshToken } });
  return res.statusCode;
}

async function setup() {
  const deps = await makeTestDeps({ clients: [app1, app2] });
  const app = buildServer(deps);
  return { deps, app };
}

describe('T12: смена аккаунта в одном браузере', () => {
  it('прежний аккаунт гаснет во всех приложениях этого браузера, но не на другом устройстве', async () => {
    const { app } = await setup();
    try {
      const laptop = browser(app);
      const aliceApp1 = await laptop.login(app1, 'alice@x.com');
      const aliceApp2 = await laptop.silent(app2);
      const phone = browser(app);
      const alicePhone = await phone.login(app2, 'alice@x.com');

      const bobApp1 = await laptop.login(app1, 'bob@x.com');

      expect(await refreshStatus(app, aliceApp2)).toBe(400);
      expect(await refreshStatus(app, aliceApp1)).toBe(400);
      expect(await refreshStatus(app, alicePhone)).toBe(200);
      expect(await refreshStatus(app, bobApp1)).toBe(200);
      // Приложение 2 по SSO теперь входит под Бобом.
      expect(await refreshStatus(app, await laptop.silent(app2))).toBe(200);
    } finally { await app.close(); }
  });

  it('выход после смены аккаунта гасит всё в этом браузере и не трогает чужой аккаунт на другом устройстве', async () => {
    const { app } = await setup();
    try {
      const laptop = browser(app);
      await laptop.login(app1, 'alice@x.com');
      await laptop.silent(app2);
      const phone = browser(app);
      const alicePhone = await phone.login(app2, 'alice@x.com');
      const bobApp1 = await laptop.login(app1, 'bob@x.com');
      const bobApp2 = await laptop.silent(app2);

      expect((await laptop.logout(app2)).statusCode).toBe(200);

      expect(await refreshStatus(app, bobApp1)).toBe(400);
      expect(await refreshStatus(app, bobApp2)).toBe(400);
      expect(await refreshStatus(app, alicePhone)).toBe(200);
    } finally { await app.close(); }
  });

  it('повторный вход тем же пользователем не гасит его сессии в других приложениях', async () => {
    const { app } = await setup();
    try {
      const laptop = browser(app);
      await laptop.login(app1, 'alice@x.com');
      const aliceApp2 = await laptop.silent(app2);
      await laptop.login(app1, 'alice@x.com');
      expect(await refreshStatus(app, aliceApp2)).toBe(200);
    } finally { await app.close(); }
  });

  it('P3-4: код прежнего входа того же пользователя обменивается и после повторного входа', async () => {
    const { app } = await setup();
    try {
      const laptop = browser(app);
      await laptop.login(app1, 'alice@x.com');
      const silentRes = await app.inject({ method: 'GET',
        headers: { cookie: `csrf=${TEST_CSRF}; sso=${laptop.sso}` },
        url: `/authorize?${new URLSearchParams(oidc(app2, { prompt: 'none', response_type: 'code' })).toString()}` });
      const code = new URL(String(silentRes.headers.location)).searchParams.get('code')!;
      await laptop.login(app1, 'alice@x.com');
      const res = await app.inject({ method: 'POST', url: '/oauth/token', payload: { grant_type: 'authorization_code',
        code, client_id: app2.id, redirect_uri: app2.redirectUris[0]!, code_verifier: TEST_VERIFIER } });
      expect(res.statusCode).toBe(200);
      // Сессия из этого кода привязана к цепочке: смена аккаунта её гасит.
      await laptop.login(app1, 'bob@x.com');
      expect(await refreshStatus(app, res.json().refresh_token)).toBe(400);
    } finally { await app.close(); }
  });

  it('код тихого входа, выданный до смены аккаунта, после неё не обменивается', async () => {
    const { app } = await setup();
    try {
      const laptop = browser(app);
      await laptop.login(app1, 'alice@x.com');
      const silentRes = await app.inject({ method: 'GET',
        headers: { cookie: `csrf=${TEST_CSRF}; sso=${laptop.sso}` },
        url: `/authorize?${new URLSearchParams(oidc(app2, { prompt: 'none', response_type: 'code' })).toString()}` });
      const code = new URL(String(silentRes.headers.location)).searchParams.get('code')!;
      await laptop.login(app1, 'bob@x.com');
      const res = await app.inject({ method: 'POST', url: '/oauth/token', payload: { grant_type: 'authorization_code',
        code, client_id: app2.id, redirect_uri: app2.redirectUris[0]!, code_verifier: TEST_VERIFIER } });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe('invalid_grant');
    } finally { await app.close(); }
  });
});

describe('T04: выход повторяем после частичного сбоя', () => {
  it('отзыв сессий упал после отзыва SSO — повторный выход всё равно гасит сессии', async () => {
    const { deps, app } = await setup();
    try {
      const laptop = browser(app);
      const app1Token = await laptop.login(app1, 'alice@x.com');
      const app2Token = await laptop.silent(app2);
      const store = deps.ssoStores.sessions;
      const original = store.revokeForSsoChain.bind(store);
      let failures = 1;
      store.revokeForSsoChain = async (...args: Parameters<typeof original>) => {
        if (failures-- > 0) throw new Error('db down');
        return original(...args);
      };
      const failed = await laptop.logout(app1);
      expect(failed.statusCode).toBe(500);
      expect(failed.headers['content-type']).toMatch(/text\/html/);
      const retried = await laptop.logout(app1);
      expect(retried.statusCode).toBe(200);
      expect(await refreshStatus(app, app1Token)).toBe(400);
      expect(await refreshStatus(app, app2Token)).toBe(400);
    } finally { await app.close(); }
  });
});
