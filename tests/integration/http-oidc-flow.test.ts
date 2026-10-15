import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../src/adapters/http/server.js';
import {
  makeTestDeps,
  authorizeForm,
  extractChallenge,
  TEST_VERIFIER,
  TEST_CHALLENGE,
  FORM_HEADERS,
  type TestDeps,
} from '../adapters/http/helpers.js';

// Одни заголовки на все POST: несут csrf-cookie для форм входа; на /oauth/token
// (csrf не проверяется) лишняя cookie безвредна.
const FORM = FORM_HEADERS;
const REDIRECT_URI = 'https://app.example/cb';

function authorizeQuery(): string {
  return new URLSearchParams({
    client_id: 'app',
    redirect_uri: REDIRECT_URI,
    code_challenge: TEST_CHALLENGE,
    code_challenge_method: 'S256',
    scope: 'openid profile email',
    state: 'st1',
  }).toString();
}

// Сквозной OIDC-путь на едином deps/app: фиксированные часы makeTestDeps
// держат токены живыми на всём сценарии, поэтому шаги идут по порядку.
describe('HTTP OIDC flow', () => {
  let deps: TestDeps;
  let app: FastifyInstance;
  let code: string;
  let accessToken: string;
  let firstRefreshToken: string;

  beforeAll(async () => {
    deps = await makeTestDeps();
    app = buildServer(deps);
  });

  afterAll(async () => {
    await app.close();
  });

  it('1. GET /authorize показывает форму входа по почте', async () => {
    const res = await app.inject({ method: 'GET', url: `/authorize?${authorizeQuery()}` });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('/authorize/identify');
  });

  it('2. identify (отправка кода) + code/verify → 302 с кодом и state', async () => {
    const identify = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: authorizeForm({ email: 'user@x.com' }),
      headers: FORM,
    });
    const challenge = extractChallenge(identify.body);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/code/verify',
      payload: authorizeForm({ challenge, code: 'CODE55' }),
      headers: FORM,
    });
    expect(res.statusCode).toBe(302);
    const location = new URL(res.headers['location'] as string);
    const returnedCode = location.searchParams.get('code');
    expect(returnedCode).toBeTruthy();
    expect(location.searchParams.get('state')).toBe('st1');
    code = returnedCode as string;
  });

  it('3. POST /oauth/token (authorization_code) → полная пара токенов', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: 'app',
        code_verifier: TEST_VERIFIER,
      }).toString(),
      headers: FORM,
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(typeof body.access_token).toBe('string');
    expect(typeof body.id_token).toBe('string');
    expect(typeof body.refresh_token).toBe('string');
    expect(body.token_type).toBe('Bearer');
    expect(typeof body.expires_in).toBe('number');
    accessToken = body.access_token;
    firstRefreshToken = body.refresh_token;
  });

  it('4. GET /userinfo с access_token → профиль', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/userinfo',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.email).toBe('user@x.com');
    // Вход по коду доказывает владение почтой → email_verified=true.
    expect(body.email_verified).toBe(true);
    expect(typeof body.sub).toBe('string');
    expect(body.sub.length).toBeGreaterThan(0);
  });

  it('5. POST /oauth/token (refresh_token) → новая пара, новый refresh', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: firstRefreshToken,
      }).toString(),
      headers: FORM,
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(typeof body.access_token).toBe('string');
    expect(typeof body.id_token).toBe('string');
    expect(typeof body.refresh_token).toBe('string');
    expect(body.refresh_token).not.toBe(firstRefreshToken);
    expect(body.token_type).toBe('Bearer');
    expect(typeof body.expires_in).toBe('number');
  });

  it('6. discovery и jwks доступны', async () => {
    const discovery = await app.inject({
      method: 'GET',
      url: '/.well-known/openid-configuration',
    });
    expect(discovery.statusCode).toBe(200);

    const jwks = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(jwks.statusCode).toBe(200);
    expect(jwks.json().keys[0].kty).toBe('RSA');
  });

  it('7. повторный обмен того же кода → invalid_grant', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: 'app',
        code_verifier: TEST_VERIFIER,
      }).toString(),
      headers: FORM,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: 'invalid_grant' });
  });
});
