import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, type TestDeps, TEST_CSRF, FORM_HEADERS, extractChallenge } from './helpers.js';
import type { Client } from '../../../src/domain/clients/client.js';

const LOGOUT_CLIENT: Client = {
  id: 'app',
  type: 'external',
  redirectUris: ['https://app.example/cb'],
  allowedProviders: ['email'],
  postLogoutRedirectUris: ['https://app.example/after-logout'],
};

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

function getSetCookieLines(res: { headers: Record<string, unknown> }): string[] {
  const raw = res.headers['set-cookie'];
  return Array.isArray(raw) ? raw : [String(raw ?? '')];
}

function getCookie(res: { headers: Record<string, unknown> }, name: string): string {
  for (const line of getSetCookieLines(res)) {
    const m = new RegExp(`${name}=([^;]+)`).exec(line);
    if (m && m[1] !== undefined) return m[1];
  }
  throw new Error(`cookie ${name} not found`);
}

// Реальный вход по коду → sso-cookie: identify (отправка) → code/verify (обмен).
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

// Забирает csrf cookie + значение поля csrf из HTML confirm-страницы GET /logout.
async function getLogoutCsrf(
  app: Awaited<ReturnType<typeof buildServer>>,
  query: Record<string, string>,
): Promise<{ csrfCookie: string; csrfField: string; res: Awaited<ReturnType<typeof app.inject>> }> {
  const res = await app.inject({
    method: 'GET',
    url: `/logout?${new URLSearchParams(query).toString()}`,
  });
  const csrfCookie = getCookie(res, 'csrf');
  const csrfField = /name="csrf" value="([^"]+)"/.exec(res.body)?.[1] ?? '';
  return { csrfCookie, csrfField, res };
}

// Заводит device-сессию для того же пользователя, что и в активной SSO-сессии.
async function startDeviceSession(deps: TestDeps, sso: string, clientId: string): Promise<void> {
  const session = await deps.sso.resolve(sso);
  if (!session) throw new Error('нет активной SSO-сессии');
  await deps.sessions.start({
    userId: session.userId,
    clientId,
    provider: 'email',
    profile: { email: 'user@x.com' },
    scope: 'openid profile email',
    device: { userAgent: 'test', ip: '127.0.0.1' },
  });
}

describe('GET /logout', () => {
  it('валидный client_id → 200 confirm-страница + csrf cookie', async () => {
    const app = buildServer(await makeTestDeps({ clients: [LOGOUT_CLIENT] }));
    const res = await app.inject({ method: 'GET', url: '/logout?client_id=app' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('action="/logout"');
    expect(res.body).toContain('name="client_id" value="app"');
    expect(getSetCookieLines(res).some((l) => l.includes('csrf='))).toBe(true);
    await app.close();
  });

  it('неизвестный client_id → 400', async () => {
    const app = buildServer(await makeTestDeps({ clients: [LOGOUT_CLIENT] }));
    const res = await app.inject({ method: 'GET', url: '/logout?client_id=nope' });
    expect(res.statusCode).toBe(400);
    await app.close();
  });

  it('post_logout_redirect_uri из белого списка попадает в форму', async () => {
    const app = buildServer(await makeTestDeps({ clients: [LOGOUT_CLIENT] }));
    const res = await app.inject({
      method: 'GET',
      url: `/logout?${new URLSearchParams({
        client_id: 'app',
        post_logout_redirect_uri: 'https://app.example/after-logout',
      }).toString()}`,
    });
    expect(res.body).toContain('name="post_logout_redirect_uri" value="https://app.example/after-logout"');
    await app.close();
  });

  it('посторонний post_logout_redirect_uri в форму не попадает', async () => {
    const app = buildServer(await makeTestDeps({ clients: [LOGOUT_CLIENT] }));
    const res = await app.inject({
      method: 'GET',
      url: `/logout?${new URLSearchParams({
        client_id: 'app',
        post_logout_redirect_uri: 'https://evil.example/x',
      }).toString()}`,
    });
    expect(res.body).not.toContain('name="post_logout_redirect_uri"');
    await app.close();
  });
});

describe('POST /logout', () => {
  it('валидный csrf + активная SSO → гасит sso, отзывает SSO и device-сессии', async () => {
    const deps = await makeTestDeps({ clients: [LOGOUT_CLIENT] });
    const app = buildServer(deps);
    const sso = await loginAndGetSso(app);
    await startDeviceSession(deps, sso, 'app');

    const session = await deps.sso.resolve(sso);
    const userId = session!.userId;
    const before = await deps.sessions.listForUser(userId);
    expect(before.length).toBe(1);

    const { csrfCookie, csrfField } = await getLogoutCsrf(app, { client_id: 'app' });

    const res = await app.inject({
      method: 'POST',
      url: '/logout',
      payload: new URLSearchParams({ client_id: 'app', csrf: csrfField }).toString(),
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: `sso=${sso}; csrf=${csrfCookie}`,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('вышли');

    // sso-cookie погашена.
    const ssoClear = getSetCookieLines(res).find((l) => l.startsWith('sso='));
    expect(ssoClear).toBeTruthy();
    expect(/Max-Age=0|Expires=Thu, 01 Jan 1970/.test(ssoClear ?? '')).toBe(true);

    // Device-сессии клиента отозваны.
    const after = await deps.sessions.listForUser(userId);
    expect(after.length).toBe(0);

    // Старая SSO-cookie больше не даёт согласие: GET /authorize → форма входа.
    const authRes = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams(oidc()).toString()}`,
      headers: { cookie: `sso=${sso}` },
    });
    expect(authRes.statusCode).toBe(200);
    expect(authRes.body).toContain('/authorize/identify');
    expect(authRes.body).not.toContain('/authorize/confirm');

    await app.close();
  });

  it('«Выйти во всех приложениях» отзывает сессии пользователя во всех клиентах', async () => {
    const other: Client = { id: 'other', type: 'internal', redirectUris: ['https://other.example/cb'], allowedProviders: ['email'] };
    const deps = await makeTestDeps({ clients: [LOGOUT_CLIENT, other] });
    const app = buildServer(deps);
    const sso = await loginAndGetSso(app);
    await startDeviceSession(deps, sso, 'app');
    await startDeviceSession(deps, sso, 'other');
    const userId = (await deps.sso.resolve(sso))!.userId;
    expect((await deps.sessions.listForUser(userId)).length).toBe(2);

    const { csrfCookie, csrfField } = await getLogoutCsrf(app, { client_id: 'app' });
    const res = await app.inject({
      method: 'POST',
      url: '/logout',
      payload: new URLSearchParams({ client_id: 'app', csrf: csrfField }).toString(),
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: `sso=${sso}; csrf=${csrfCookie}`,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(await deps.sessions.listForUser(userId)).toEqual([]);
    expect(await deps.sso.resolve(sso)).toBeNull();
    await app.close();
  });

  it('post_logout_redirect_uri из белого списка → 302 на него', async () => {
    const deps = await makeTestDeps({ clients: [LOGOUT_CLIENT] });
    const app = buildServer(deps);
    const sso = await loginAndGetSso(app);
    const { csrfCookie, csrfField } = await getLogoutCsrf(app, {
      client_id: 'app',
      post_logout_redirect_uri: 'https://app.example/after-logout',
    });

    const res = await app.inject({
      method: 'POST',
      url: '/logout',
      payload: new URLSearchParams({
        client_id: 'app',
        post_logout_redirect_uri: 'https://app.example/after-logout',
        csrf: csrfField,
      }).toString(),
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: `sso=${sso}; csrf=${csrfCookie}`,
      },
    });
    expect(res.statusCode).toBe(302);
    expect(res.headers['location']).toBe('https://app.example/after-logout');
    await app.close();
  });

  it('посторонний post_logout_redirect_uri → 200 loggedOut без редиректа', async () => {
    const deps = await makeTestDeps({ clients: [LOGOUT_CLIENT] });
    const app = buildServer(deps);
    const { csrfCookie, csrfField } = await getLogoutCsrf(app, { client_id: 'app' });

    const res = await app.inject({
      method: 'POST',
      url: '/logout',
      payload: new URLSearchParams({
        client_id: 'app',
        post_logout_redirect_uri: 'https://evil.example/x',
        csrf: csrfField,
      }).toString(),
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: `csrf=${csrfCookie}`,
      },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['location']).toBeUndefined();
    expect(res.body).toContain('вышли');
    await app.close();
  });

  it('неверный csrf → 400', async () => {
    const app = buildServer(await makeTestDeps({ clients: [LOGOUT_CLIENT] }));
    const res = await app.inject({
      method: 'POST',
      url: '/logout',
      payload: new URLSearchParams({ client_id: 'app', csrf: 'wrong' }).toString(),
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: 'csrf=realvalue',
      },
    });
    expect(res.statusCode).toBe(400);
    await app.close();
  });

  it('без csrf-поля → 400', async () => {
    const app = buildServer(await makeTestDeps({ clients: [LOGOUT_CLIENT] }));
    const res = await app.inject({
      method: 'POST',
      url: '/logout',
      payload: new URLSearchParams({ client_id: 'app' }).toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    expect(res.statusCode).toBe(400);
    await app.close();
  });
});
