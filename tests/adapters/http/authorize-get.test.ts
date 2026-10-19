import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps } from './helpers.js';

function query(overrides: Record<string, string> = {}): string {
  const base: Record<string, string> = {
    client_id: 'app',
    redirect_uri: 'https://app.example/cb',
    response_type: 'code',
    code_challenge: 'chal',
    code_challenge_method: 'S256',
    scope: 'openid',
    state: 'st1',
  };
  return new URLSearchParams({ ...base, ...overrides }).toString();
}

const INTERNAL_CLIENT = {
  id: 'app',
  type: 'internal' as const,
  redirectUris: ['https://app.example/cb'],
  allowedProviders: ['email'],
};

describe('GET /authorize', () => {
  it('валидный запрос отдаёт страницу входа', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({ method: 'GET', url: `/authorize?${query()}` });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toContain('/authorize/identify');
    await app.close();
  });

  it('неизвестный client_id → 400', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query({ client_id: 'nope' })}`,
    });
    expect(res.statusCode).toBe(400);
    expect(res.headers['content-type']).toContain('text/html');
    await app.close();
  });

  it('code_challenge_method=plain → редирект с error=invalid_request', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query({ code_challenge_method: 'plain' })}`,
    });
    expect(res.statusCode).toBe(302);
    const location = res.headers['location'] as string;
    expect(location.startsWith('https://app.example/cb')).toBe(true);
    expect(location).toContain('error=invalid_request');
    expect(location).toContain('error_description=');
    expect(location).toContain('state=st1');
    await app.close();
  });

  it('response_type=token → редирект с error=unsupported_response_type', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query({ response_type: 'token' })}`,
    });
    expect(res.statusCode).toBe(302);
    const location = res.headers['location'] as string;
    expect(location.startsWith('https://app.example/cb')).toBe(true);
    expect(location).toContain('error=unsupported_response_type');
    expect(location).toContain('state=st1');
    await app.close();
  });

  it('prompt=none без SSO-сессии → редирект с error=login_required', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query({ prompt: 'none' })}`,
    });
    expect(res.statusCode).toBe(302);
    const location = res.headers['location'] as string;
    expect(location.startsWith('https://app.example/cb')).toBe(true);
    expect(location).toContain('error=login_required');
    expect(location).toContain('state=st1');
    await app.close();
  });

  it('prompt=none с валидной SSO-сессией → тихий редирект с кодом (internal)', async () => {
    const deps = await makeTestDeps({ clients: [INTERNAL_CLIENT] });
    const { rawToken } = await deps.sso.start('user-1', {
      provider: 'email',
      email: 'user@x.com',
      emailVerified: true,
    });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query({ prompt: 'none' })}`,
      headers: { cookie: `sso=${rawToken}` },
    });
    expect(res.statusCode).toBe(302);
    const location = res.headers['location'] as string;
    expect(location.startsWith('https://app.example/cb')).toBe(true);
    expect(location).toContain('code=');
    expect(location).not.toContain('error=');
    expect(location).toContain('state=st1');
    await app.close();
  });

  it('prompt=none для external с живой SSO → consent_required, без кода и профиля', async () => {
    const deps = await makeTestDeps({
      clients: [{ id: 'app', type: 'external', redirectUris: ['https://app.example/cb'], allowedProviders: ['email'] }],
    });
    const { rawToken } = await deps.sso.start('user-1', {
      provider: 'email',
      email: 'user@x.com',
      emailVerified: true,
    });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query({ prompt: 'none' })}`,
      headers: { cookie: `sso=${rawToken}` },
    });
    expect(res.statusCode).toBe(302);
    const location = res.headers['location'] as string;
    expect(location).toContain('error=consent_required');
    expect(location).not.toContain('code=');
    expect(location).toContain('state=st1');
    await app.close();
  });

  it('живая SSO-cookie продлевается при показе экрана согласия (скользящий срок)', async () => {
    const deps = await makeTestDeps();
    const { rawToken } = await deps.sso.start('user-1', {
      provider: 'email',
      email: 'user@x.com',
      emailVerified: true,
    });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query()}`,
      headers: { cookie: `sso=${rawToken}` },
    });
    expect(res.statusCode).toBe(200);
    const raw = res.headers['set-cookie'];
    const lines = Array.isArray(raw) ? raw : raw ? [raw] : [];
    const sso = lines.find((l) => l.startsWith('sso='));
    expect(sso).toBeDefined();
    expect(sso).toContain(`sso=${rawToken}`);
    expect(sso).toContain(`Max-Age=${deps.config.ssoTtlSeconds}`);
    await app.close();
  });

  it('открытие экрана согласия не ротирует существующий csrf (другие вкладки не ломаются)', async () => {
    const deps = await makeTestDeps();
    const { rawToken } = await deps.sso.start('user-1', {
      provider: 'email',
      email: 'user@x.com',
      emailVerified: true,
    });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query()}`,
      headers: { cookie: `sso=${rawToken}; csrf=existing-token` },
    });
    expect(res.statusCode).toBe(200);
    const raw = res.headers['set-cookie'];
    const lines = Array.isArray(raw) ? raw : raw ? [raw] : [];
    expect(lines.some((l) => l.startsWith('csrf='))).toBe(false);
    expect(res.body).toContain('name="csrf" value="existing-token"');
    await app.close();
  });

  it('prompt=none с SSO через запрещённый провайдер → login_required', async () => {
    const deps = await makeTestDeps();
    const { rawToken } = await deps.sso.start('user-1', {
      provider: 'google',
      email: 'user@x.com',
      emailVerified: true,
    });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query({ prompt: 'none' })}`,
      headers: { cookie: `sso=${rawToken}` },
    });
    expect(res.statusCode).toBe(302);
    const location = res.headers['location'] as string;
    expect(location).toContain('error=login_required');
    expect(location).not.toContain('error=unauthorized_client');
    await app.close();
  });

  it('без SSO-cookie → форма входа', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({ method: 'GET', url: `/authorize?${query()}` });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('/authorize/identify');
    expect(res.body).not.toContain('/authorize/confirm');
    await app.close();
  });

  it('с валидной SSO-cookie → экран согласия и выставленный csrf', async () => {
    const deps = await makeTestDeps();
    const { rawToken } = await deps.sso.start('user-1', {
      provider: 'email',
      email: 'user@x.com',
      emailVerified: true,
    });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query()}`,
      headers: { cookie: `sso=${rawToken}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toContain('/authorize/confirm');
    expect(res.body).toContain('Продолжить как');
    expect(res.body).toContain('user@x.com');
    const setCookie = res.headers['set-cookie'];
    const cookieStr = Array.isArray(setCookie) ? setCookie.join('\n') : String(setCookie ?? '');
    expect(cookieStr).toMatch(/csrf=[^;]+/);
    await app.close();
  });

  it('SSO через запрещённый провайдер → форма разрешённого входа, не согласие', async () => {
    const deps = await makeTestDeps();
    const { rawToken } = await deps.sso.start('user-1', {
      provider: 'google',
      email: 'user@x.com',
      emailVerified: true,
    });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query()}`,
      headers: { cookie: `sso=${rawToken}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('/authorize/identify');
    expect(res.body).not.toContain('/authorize/confirm');
    expect(res.body).not.toContain('Продолжить как');
    await app.close();
  });

  it('с валидной SSO-cookie но prompt=login → форма входа', async () => {
    const deps = await makeTestDeps();
    const { rawToken } = await deps.sso.start('user-1', {
      provider: 'email',
      email: 'user@x.com',
      emailVerified: true,
    });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${query({ prompt: 'login' })}`,
      headers: { cookie: `sso=${rawToken}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('/authorize/identify');
    expect(res.body).not.toContain('/authorize/confirm');
    const csrfField = res.body.match(/name="csrf" value="([^"]+)"/);
    expect(csrfField?.[1]).toBeTruthy();
    const setCookie = res.headers['set-cookie'];
    const cookieStr = Array.isArray(setCookie) ? setCookie.join('\n') : String(setCookie ?? '');
    expect(cookieStr).toContain(`csrf=${csrfField?.[1]}`);
    await app.close();
  });
});
