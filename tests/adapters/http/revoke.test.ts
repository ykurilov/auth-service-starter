import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, loginWithCode, TEST_VERIFIER, FORM_HEADERS } from './helpers.js';
import type { FastifyInstance } from 'fastify';

function form(fields: Record<string, string>): string {
  return new URLSearchParams(fields).toString();
}

async function obtainRefreshToken(app: FastifyInstance): Promise<string> {
  const code = await loginWithCode(app);
  const res = await app.inject({
    method: 'POST',
    url: '/oauth/token',
    payload: form({
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'https://app.example/cb',
      client_id: 'app',
      code_verifier: TEST_VERIFIER,
    }),
    headers: FORM_HEADERS,
  });
  return res.json().refresh_token as string;
}

describe('POST /oauth/revoke', () => {
  it('отзывает refresh-токен: последующий refresh_token → 400 invalid_grant', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const refreshToken = await obtainRefreshToken(app);

    const revokeRes = await app.inject({
      method: 'POST',
      url: '/oauth/revoke',
      payload: form({ token: refreshToken }),
      headers: FORM_HEADERS,
    });
    expect(revokeRes.statusCode).toBe(200);
    expect(revokeRes.body).toBe('');

    const tokenRes = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: form({ grant_type: 'refresh_token', refresh_token: refreshToken }),
      headers: FORM_HEADERS,
    });
    expect(tokenRes.statusCode).toBe(400);
    expect(tokenRes.json().error).toBe('invalid_grant');
    await app.close();
  });

  it('неизвестный токен → всё равно 200', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);

    const res = await app.inject({
      method: 'POST',
      url: '/oauth/revoke',
      payload: form({ token: 'unknown-token' }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(200);
    await app.close();
  });

  it('нет поля token → 400 invalid_request', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);

    const res = await app.inject({
      method: 'POST',
      url: '/oauth/revoke',
      payload: form({}),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
    await app.close();
  });

  it('после N попыток 429 c Retry-After', async () => {
    const deps = await makeTestDeps({ rateLimits: { revoke: { limit: 2, windowSeconds: 60 } } });
    const app = buildServer(deps);

    const first = await app.inject({ method: 'POST', url: '/oauth/revoke', payload: form({ token: 'a' }), headers: FORM_HEADERS });
    const second = await app.inject({ method: 'POST', url: '/oauth/revoke', payload: form({ token: 'a' }), headers: FORM_HEADERS });
    const third = await app.inject({ method: 'POST', url: '/oauth/revoke', payload: form({ token: 'a' }), headers: FORM_HEADERS });

    expect(first.statusCode).not.toBe(429);
    expect(second.statusCode).not.toBe(429);
    expect(third.statusCode).toBe(429);
    expect(third.headers['retry-after']).toBeDefined();
    await app.close();
  });
});
