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
});
