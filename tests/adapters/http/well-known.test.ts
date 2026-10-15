import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps } from './helpers.js';

describe('OIDC discovery', () => {
  it('отдаёт корректный openid-configuration', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'GET',
      url: '/.well-known/openid-configuration',
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.issuer).toBe('https://auth.example');
    expect(body.authorization_endpoint).toBe('https://auth.example/authorize');
    expect(body.token_endpoint).toBe('https://auth.example/oauth/token');
    expect(body.userinfo_endpoint).toBe('https://auth.example/userinfo');
    expect(body.end_session_endpoint).toBe('https://auth.example/logout');
    expect(body.revocation_endpoint).toBe('https://auth.example/oauth/revoke');
    expect(body.jwks_uri).toBe('https://auth.example/.well-known/jwks.json');
    expect(body.response_types_supported).toEqual(['code']);
    expect(body.grant_types_supported).toEqual(['authorization_code', 'refresh_token']);
    expect(body.code_challenge_methods_supported).toEqual(['S256']);
    expect(body.id_token_signing_alg_values_supported).toEqual(['RS256']);
    await app.close();
  });
});

describe('JWKS endpoint', () => {
  it('отдаёт публичный ключ', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'GET',
      url: '/.well-known/jwks.json',
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(Array.isArray(body.keys)).toBe(true);
    expect(body.keys[0].kty).toBe('RSA');
    expect(body.keys[0].use).toBe('sig');
    await app.close();
  });
});
