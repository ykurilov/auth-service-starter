import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CSRF, FORM_HEADERS } from './helpers.js';

function form(overrides: Record<string, string> = {}): string {
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

describe('POST /authorize/identify', () => {
  it('любая почта → экран ввода кода из письма', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: form(),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(200);
    // Единственный способ входа по почте — код: сразу экран ввода кода.
    expect(res.body).toContain('/authorize/code/verify');
    expect(res.body).toContain('<strong>user@x.com</strong>');
    expect(res.body).toContain('name="challenge"');
    // Пароля и регистрации больше нет.
    expect(res.body).not.toContain('/authorize/password');
    expect(res.body).not.toContain('/authorize/register');
    await app.close();
  });

  it('незнакомая почта → тот же экран кода (наличие аккаунта не раскрываем)', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: form({ email: 'new@x.com' }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('/authorize/code/verify');
    expect(res.body).toContain('<strong>new@x.com</strong>');
    expect(res.body).toContain('name="challenge"');
    await app.close();
  });

  it('регистр и пробелы в почте нормализуются', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: form({ email: '  User@X.com ' }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('<strong>user@x.com</strong>');
    expect(res.body).toContain('name="challenge"');
    await app.close();
  });

  it('подделанный client_id → 400', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: form({ client_id: 'evil' }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(400);
    await app.close();
  });

  it('превышение лимита запроса кода (ip+email) → 429', async () => {
    const deps = await makeTestDeps();
    deps.config.rateLimits.codeRequest = { limit: 2, windowSeconds: 900 };
    const app = buildServer(deps);
    const inject = () =>
      app.inject({
        method: 'POST',
        url: '/authorize/identify',
        payload: form(),
        headers: FORM_HEADERS,
      });
    await inject();
    await inject();
    const res = await inject();
    expect(res.statusCode).toBe(429);
    expect(res.headers['retry-after']).toBeDefined();
    await app.close();
  });
});
