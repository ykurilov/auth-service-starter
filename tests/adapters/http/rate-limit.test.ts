import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, loginWithCode, TEST_CSRF, FORM_HEADERS } from './helpers.js';

// Форма шага «Получить код»: OIDC-параметры + email, без пароля.
function identifyForm(overrides: Record<string, string> = {}): string {
  const base: Record<string, string> = {
    client_id: 'app',
    redirect_uri: 'https://app.example/cb',
    code_challenge: 'chal',
    code_challenge_method: 'S256',
    scope: 'openid',
    state: 'st1',
    csrf: TEST_CSRF,
    email: 'user@x.com',
  };
  return new URLSearchParams({ ...base, ...overrides }).toString();
}

function tokenForm(): string {
  return new URLSearchParams({
    grant_type: 'authorization_code',
    code: 'nope',
    redirect_uri: 'https://app.example/cb',
    client_id: 'app',
    code_verifier: 'v',
  }).toString();
}

describe('rate limiting on sensitive endpoints', () => {
  it('POST /authorize/identify: тот же ip+email → 3-я попытка 429 с Retry-After', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeRequest: { limit: 2, windowSeconds: 60 } } });
    const app = buildServer(deps);

    const first = await app.inject({ method: 'POST', url: '/authorize/identify', payload: identifyForm(), headers: FORM_HEADERS });
    const second = await app.inject({ method: 'POST', url: '/authorize/identify', payload: identifyForm(), headers: FORM_HEADERS });
    const third = await app.inject({ method: 'POST', url: '/authorize/identify', payload: identifyForm(), headers: FORM_HEADERS });

    expect(first.statusCode).not.toBe(429);
    expect(second.statusCode).not.toBe(429);
    expect(third.statusCode).toBe(429);
    expect(third.headers['retry-after']).toBeDefined();
    expect(third.body).toContain('Слишком много попыток');
    await app.close();
  });

  it('POST /authorize/identify: разные email не блокируют друг друга', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeRequest: { limit: 2, windowSeconds: 60 } } });
    const app = buildServer(deps);

    await app.inject({ method: 'POST', url: '/authorize/identify', payload: identifyForm({ email: 'a@x.com' }), headers: FORM_HEADERS });
    await app.inject({ method: 'POST', url: '/authorize/identify', payload: identifyForm({ email: 'a@x.com' }), headers: FORM_HEADERS });
    const blockedA = await app.inject({ method: 'POST', url: '/authorize/identify', payload: identifyForm({ email: 'a@x.com' }), headers: FORM_HEADERS });
    const otherEmail = await app.inject({ method: 'POST', url: '/authorize/identify', payload: identifyForm({ email: 'b@x.com' }), headers: FORM_HEADERS });

    expect(blockedA.statusCode).toBe(429);
    expect(otherEmail.statusCode).not.toBe(429);
    await app.close();
  });

  it('POST /oauth/token: после N попыток 429 c Retry-After', async () => {
    const deps = await makeTestDeps({ rateLimits: { token: { limit: 2, windowSeconds: 60 } } });
    const app = buildServer(deps);

    const first = await app.inject({ method: 'POST', url: '/oauth/token', payload: tokenForm(), headers: FORM_HEADERS });
    const second = await app.inject({ method: 'POST', url: '/oauth/token', payload: tokenForm(), headers: FORM_HEADERS });
    const third = await app.inject({ method: 'POST', url: '/oauth/token', payload: tokenForm(), headers: FORM_HEADERS });

    expect(first.statusCode).not.toBe(429);
    expect(second.statusCode).not.toBe(429);
    expect(third.statusCode).toBe(429);
    expect(third.headers['retry-after']).toBeDefined();
    await app.close();
  });

  it('успешный вход в пределах лимита работает как раньше (не 429)', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeRequest: { limit: 5, windowSeconds: 60 } } });
    const app = buildServer(deps);

    // identify (отправка кода) + code/verify (обмен) укладываются в лимит и
    // выдают authorization code, без 429.
    const code = await loginWithCode(app);
    expect(code).toBeTruthy();
    await app.close();
  });
});
