import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, authorizeForm, extractChallenge, TEST_CSRF, FORM_HEADERS } from './helpers.js';

// Защита от подброса cookie с соседнего поддомена (cookie tossing) и от
// кросс-origin POST: __Host- имена на HTTPS, проверка Origin/Sec-Fetch-Site.

function setCookies(res: { headers: Record<string, unknown> }): string[] {
  const raw = res.headers['set-cookie'];
  return Array.isArray(raw) ? (raw as string[]) : raw ? [String(raw)] : [];
}

const authorizeQuery =
  'client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_challenge=chalchalchalchalchalchalchalchalchalchalchal' +
  '&code_challenge_method=S256&scope=openid&state=st1';

async function secureApp() {
  const deps = await makeTestDeps();
  deps.config.ssoCookieSecure = true;
  return { deps, app: buildServer(deps) };
}

describe('__Host- cookie на HTTPS', () => {
  it('csrf выпускается как __Host-csrf: Secure, Path=/, без Domain', async () => {
    const { app } = await secureApp();
    const res = await app.inject({ method: 'GET', url: `/authorize?${authorizeQuery}` });
    const line = setCookies(res).find((l) => l.startsWith('__Host-csrf='));
    expect(line).toBeDefined();
    expect(line).toContain('Secure');
    expect(line).toContain('Path=/');
    expect(line).not.toMatch(/Domain=/i);
    expect(setCookies(res).some((l) => l.startsWith('csrf='))).toBe(false);
    await app.close();
  });

  it('подброшенная legacy-cookie csrf без префикса на HTTPS не принимается', async () => {
    const { deps, app } = await secureApp();
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: authorizeForm({ email: 'user@x.com' }),
      headers: FORM_HEADERS, // cookie: csrf=<значение поля>
    });
    expect(res.statusCode).toBe(400);
    expect(deps.mailer.sent).toHaveLength(0);
    await app.close();
  });

  it('вход по коду на HTTPS ставит __Host-sso; legacy sso= не даёт тихого входа', async () => {
    const { deps, app } = await secureApp();
    const headers = { 'content-type': 'application/x-www-form-urlencoded', cookie: `__Host-csrf=${TEST_CSRF}` };
    const identify = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: authorizeForm({ email: 'user@x.com' }),
      headers,
    });
    const challenge = extractChallenge(identify.body);
    const verify = await app.inject({
      method: 'POST',
      url: '/authorize/code/verify',
      payload: authorizeForm({ challenge, code: 'CODE55' }),
      headers,
    });
    expect(verify.statusCode).toBe(302);
    const sso = setCookies(verify).find((l) => l.startsWith('__Host-sso='));
    expect(sso).toContain('Secure');
    const token = /__Host-sso=([^;]+)/.exec(sso!)![1]!;
    // Тот же токен под legacy-именем (как подбросил бы соседний поддомен).
    deps.config.clients[0]!.type = 'internal';
    const legacy = await app.inject({
      method: 'GET',
      url: `/authorize?${authorizeQuery}&prompt=none`,
      headers: { cookie: `sso=${token}` },
    });
    expect(legacy.headers['location'] as string).toContain('error=login_required');
    await app.close();
  });

  it('http-разработка (Secure выключен) — обычные имена cookie', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({ method: 'GET', url: `/authorize?${authorizeQuery}` });
    expect(setCookies(res).some((l) => l.startsWith('csrf='))).toBe(true);
    await app.close();
  });
});

describe('проверка Origin на POST-формах', () => {
  const crossSite = { ...FORM_HEADERS, origin: 'https://evil.app.example' };

  it.each(['/authorize/identify', '/authorize/code/verify', '/authorize/confirm'])(
    '%s: чужой Origin (соседний поддомен) → 400 до любых действий',
    async (url) => {
      const deps = await makeTestDeps();
      const app = buildServer(deps);
      const res = await app.inject({
        method: 'POST',
        url,
        payload: authorizeForm({ email: 'user@x.com', challenge: 'x', code: '1' }),
        headers: crossSite,
      });
      expect(res.statusCode).toBe(400);
      expect(deps.mailer.sent).toHaveLength(0);
      await app.close();
    },
  );

  it('свой Origin проходит', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: authorizeForm({ email: 'user@x.com' }),
      headers: { ...FORM_HEADERS, origin: 'https://auth.example' },
    });
    expect(res.statusCode).toBe(200);
    await app.close();
  });

  it('без Origin, но Sec-Fetch-Site: same-site → 400', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: authorizeForm({ email: 'user@x.com' }),
      headers: { ...FORM_HEADERS, 'sec-fetch-site': 'same-site' },
    });
    expect(res.statusCode).toBe(400);
    await app.close();
  });

  it('POST /logout с чужим Origin → 400, SSO не гасится', async () => {
    const deps = await makeTestDeps();
    const { rawToken } = await deps.sso.start('u1', { provider: 'email', email: 'u@x.com', emailVerified: true });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/logout',
      payload: new URLSearchParams({ client_id: 'app', csrf: TEST_CSRF }).toString(),
      headers: { ...FORM_HEADERS, cookie: `csrf=${TEST_CSRF}; sso=${rawToken}`, origin: 'https://evil.app.example' },
    });
    expect(res.statusCode).toBe(400);
    expect(await deps.sso.resolve(rawToken)).not.toBeNull();
    await app.close();
  });

  it('GET /logout не ротирует существующий csrf', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'GET',
      url: '/logout?client_id=app',
      headers: { cookie: 'csrf=keep-me' },
    });
    expect(setCookies(res).some((l) => l.startsWith('csrf='))).toBe(false);
    expect(res.body).toContain('value="keep-me"');
    await app.close();
  });
});
