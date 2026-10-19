import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, loginWithCode, TEST_VERIFIER, FORM_HEADERS } from './helpers.js';
import type { FastifyInstance } from 'fastify';

async function accessToken(app: FastifyInstance, scope?: string): Promise<string> {
  const code = await loginWithCode(app, scope !== undefined ? { extra: { scope } } : {});
  const tokenRes = await app.inject({
    method: 'POST',
    url: '/oauth/token',
    payload: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'https://app.example/cb',
      client_id: 'app',
      code_verifier: TEST_VERIFIER,
    }).toString(),
    headers: FORM_HEADERS,
  });
  return tokenRes.json().access_token as string;
}

describe('GET /userinfo', () => {
  it('валидный access_token → 200 с sub, email, email_verified', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const access = await accessToken(app);

    const res = await app.inject({
      method: 'GET',
      url: '/userinfo',
      headers: { authorization: 'Bearer ' + access },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(typeof body.sub).toBe('string');
    expect(body.email).toBe('user@x.com');
    // Вход по коду доказывает владение почтой → email_verified=true.
    expect(body.email_verified).toBe(true);
    await app.close();
  });

  it('scope=openid → userinfo отдаёт только sub, без email и name (нет утечки PII)', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const access = await accessToken(app, 'openid');

    const res = await app.inject({
      method: 'GET',
      url: '/userinfo',
      headers: { authorization: 'Bearer ' + access },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(typeof body.sub).toBe('string');
    expect(body.email).toBeUndefined();
    expect(body.email_verified).toBeUndefined();
    expect(body.name).toBeUndefined();
    await app.close();
  });

  it('scope=openid email → есть email, но нет name', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const access = await accessToken(app, 'openid email');

    const res = await app.inject({
      method: 'GET',
      url: '/userinfo',
      headers: { authorization: 'Bearer ' + access },
    });
    const body = res.json();
    expect(body.email).toBe('user@x.com');
    expect(body.name).toBeUndefined();
    await app.close();
  });

  it('без заголовка Authorization → 401 invalid_token', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({ method: 'GET', url: '/userinfo' });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('invalid_token');
    await app.close();
  });

  it('мусорный токен → 401 invalid_token', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'GET',
      url: '/userinfo',
      headers: { authorization: 'Bearer garbage' },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('invalid_token');
    await app.close();
  });
  it('T30: ответ с данными пользователя не кешируется (Cache-Control: no-store)', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const access = await accessToken(app);
    const ok = await app.inject({ method: 'GET', url: '/userinfo', headers: { authorization: 'Bearer ' + access } });
    expect(ok.headers['cache-control']).toBe('no-store');
    const denied = await app.inject({ method: 'GET', url: '/userinfo' });
    expect(denied.headers['cache-control']).toBe('no-store');
    await app.close();
  });
});

describe('POST /userinfo', () => {
  it('T30: токен в заголовке Authorization → тот же ответ, что и у GET', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const access = await accessToken(app);
    const get = await app.inject({ method: 'GET', url: '/userinfo', headers: { authorization: 'Bearer ' + access } });
    const post = await app.inject({ method: 'POST', url: '/userinfo', headers: { authorization: 'Bearer ' + access } });
    expect(post.statusCode).toBe(200);
    expect(post.json()).toEqual(get.json());
    expect(post.headers['cache-control']).toBe('no-store');
    await app.close();
  });

  it('T30: токен в теле формы (access_token, RFC 6750 §2.2) → 200', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const access = await accessToken(app);
    const res = await app.inject({
      method: 'POST',
      url: '/userinfo',
      payload: new URLSearchParams({ access_token: access }).toString(),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().email).toBe('user@x.com');
    await app.close();
  });

  it('T30: токен сразу и в заголовке, и в теле → 400 invalid_request', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const access = await accessToken(app);
    const res = await app.inject({
      method: 'POST',
      url: '/userinfo',
      payload: new URLSearchParams({ access_token: access }).toString(),
      headers: { ...FORM_HEADERS, authorization: 'Bearer ' + access },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
    await app.close();
  });

  it('T30: без токена → 401 invalid_token', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({ method: 'POST', url: '/userinfo' });
    expect(res.statusCode).toBe(401);
    expect(res.headers['www-authenticate']).toBe('Bearer');
    await app.close();
  });
});
