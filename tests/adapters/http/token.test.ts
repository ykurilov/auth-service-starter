import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, loginWithCode, TEST_VERIFIER, FORM_HEADERS } from './helpers.js';

function tokenForm(fields: Record<string, string>): string {
  return new URLSearchParams(fields).toString();
}

describe('POST /oauth/token', () => {
  it('authorization_code с верным verifier → 200 с полной парой токенов', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const code = await loginWithCode(app);

    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example/cb',
        client_id: 'app',
        code_verifier: TEST_VERIFIER,
      }),
      headers: FORM_HEADERS,
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    const body = res.json();
    expect(typeof body.access_token).toBe('string');
    expect(typeof body.id_token).toBe('string');
    expect(typeof body.refresh_token).toBe('string');
    expect(body.token_type).toBe('Bearer');
    expect(typeof body.expires_in).toBe('number');
    await app.close();
  });

  it('повторный обмен тем же кодом → 400 invalid_grant', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const code = await loginWithCode(app);

    const first = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example/cb',
        client_id: 'app',
        code_verifier: TEST_VERIFIER,
      }),
      headers: FORM_HEADERS,
    });
    expect(first.statusCode).toBe(200);

    const second = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example/cb',
        client_id: 'app',
        code_verifier: TEST_VERIFIER,
      }),
      headers: FORM_HEADERS,
    });
    expect(second.statusCode).toBe(400);
    expect(second.json().error).toBe('invalid_grant');
    await app.close();
  });

  it('неверный code_verifier → 400 invalid_grant', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const code = await loginWithCode(app);

    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example/cb',
        client_id: 'app',
        code_verifier: 'wrong',
      }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_grant');
    await app.close();
  });

  it('refresh_token → 200 с новой парой, отличной от исходной', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const code = await loginWithCode(app);

    const first = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example/cb',
        client_id: 'app',
        code_verifier: TEST_VERIFIER,
      }),
      headers: FORM_HEADERS,
    });
    const initial = first.json();

    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token,
      }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(200);
    const refreshed = res.json();
    // Ротация: новый refresh_token обязан отличаться от исходного.
    expect(refreshed.refresh_token).not.toBe(initial.refresh_token);
    // Часы в тесте заморожены, поэтому JWT access_token при одинаковом iat
    // байт-в-байт совпадает — проверяем, что новая пара валидна и полна.
    expect(typeof refreshed.access_token).toBe('string');
    expect(refreshed.access_token.length).toBeGreaterThan(0);
    expect(typeof refreshed.id_token).toBe('string');
    await app.close();
  });

  it('nonce из authorize возвращается в id_token, а после refresh отсутствует', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const code = await loginWithCode(app, { extra: { nonce: 'n-777' } });

    const first = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example/cb',
        client_id: 'app',
        code_verifier: TEST_VERIFIER,
      }),
      headers: FORM_HEADERS,
    });
    expect(first.statusCode).toBe(200);
    const idPayload = (jwt: string) =>
      JSON.parse(Buffer.from(jwt.split('.')[1] ?? '', 'base64url').toString());
    expect(idPayload(first.json().id_token).nonce).toBe('n-777');

    const refreshed = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({ grant_type: 'refresh_token', refresh_token: first.json().refresh_token }),
      headers: FORM_HEADERS,
    });
    expect(refreshed.statusCode).toBe(200);
    // OIDC: nonce привязан к конкретному authorization request — в id_token
    // от refresh-ротации его быть не должно.
    expect('nonce' in idPayload(refreshed.json().id_token)).toBe(false);
    await app.close();
  });

  it('неизвестный grant_type → 400 unsupported_grant_type', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({ grant_type: 'foo' }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('unsupported_grant_type');
    await app.close();
  });

  it('инфраструктурный сбой при выдаче → 500 server_error, не invalid_grant', async () => {
    const deps = await makeTestDeps();
    deps.sessions.start = async () => {
      throw new Error('db down');
    };
    const app = buildServer(deps);
    const code = await loginWithCode(app);
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example/cb',
        client_id: 'app',
        code_verifier: TEST_VERIFIER,
      }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(500);
    expect(res.json().error).toBe('server_error');
    await app.close();
  });
});
