import { describe, it, expect } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps } from './helpers.js';

const JSON_HEADERS = { 'content-type': 'application/json' };
const AUTH = { authorization: 'Bearer secret' };

async function adminApp(): Promise<FastifyInstance> {
  // Пустой реестр + токен: роут /admin/clients смонтирован.
  const deps = await makeTestDeps({ adminApiToken: 'secret', clients: [] });
  return buildServer(deps);
}

const internalClient = {
  id: 'internal-app',
  type: 'internal',
  redirectUris: ['https://internal.example/cb'],
  allowedProviders: ['email', 'google'],
};

describe('Admin API /admin/clients', () => {
  it('без Authorization → 401', async () => {
    const app = await adminApp();
    const res = await app.inject({ method: 'GET', url: '/admin/clients' });
    expect(res.statusCode).toBe(401);
    expect(res.headers['www-authenticate']).toBe('Bearer');
  });

  it('Bearer wrong → 401', async () => {
    const app = await adminApp();
    const res = await app.inject({
      method: 'GET',
      url: '/admin/clients',
      headers: { authorization: 'Bearer wrong-длина-другая' },
    });
    expect(res.statusCode).toBe(401);
  });

  it('POST валидного internal → 201, затем виден в list и по id', async () => {
    const app = await adminApp();
    const post = await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify(internalClient),
    });
    expect(post.statusCode).toBe(201);
    expect(post.json()).toMatchObject({ id: 'internal-app', type: 'internal' });

    const list = await app.inject({ method: 'GET', url: '/admin/clients', headers: AUTH });
    expect(list.statusCode).toBe(200);
    expect(list.json().map((c: { id: string }) => c.id)).toContain('internal-app');

    const one = await app.inject({
      method: 'GET',
      url: '/admin/clients/internal-app',
      headers: AUTH,
    });
    expect(one.statusCode).toBe(200);
    expect(one.json().id).toBe('internal-app');
  });

  it('POST external с google → 400', async () => {
    const app = await adminApp();
    const res = await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify({
        id: 'ext-bad',
        type: 'external',
        redirectUris: ['https://ext.example/cb'],
        allowedProviders: ['email', 'google'],
      }),
    });
    expect(res.statusCode).toBe(400);
  });

  it('POST с http redirectUris (не localhost) → 400', async () => {
    const app = await adminApp();
    const res = await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify({
        id: 'ext-http',
        type: 'external',
        redirectUris: ['http://evil.com/cb'],
        allowedProviders: ['email'],
      }),
    });
    expect(res.statusCode).toBe(400);
  });

  it('POST external без google → 201', async () => {
    const app = await adminApp();
    const res = await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify({
        id: 'ext-ok',
        type: 'external',
        redirectUris: ['https://ext.example/cb'],
        allowedProviders: ['email'],
      }),
    });
    expect(res.statusCode).toBe(201);
  });

  it('POST дубликата id → 409', async () => {
    const app = await adminApp();
    const payload = JSON.stringify(internalClient);
    await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload,
    });
    const dup = await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload,
    });
    expect(dup.statusCode).toBe(409);
  });

  it('PATCH redirectUris существующего → 200 и значение изменилось', async () => {
    const app = await adminApp();
    await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify(internalClient),
    });
    const patch = await app.inject({
      method: 'PATCH',
      url: '/admin/clients/internal-app',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify({ redirectUris: ['https://internal.example/new'] }),
    });
    expect(patch.statusCode).toBe(200);
    expect(patch.json().redirectUris).toEqual(['https://internal.example/new']);
  });

  it('PATCH external, добавляющий google → 400', async () => {
    const app = await adminApp();
    await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify({
        id: 'ext-ok',
        type: 'external',
        redirectUris: ['https://ext.example/cb'],
        allowedProviders: ['email'],
      }),
    });
    const patch = await app.inject({
      method: 'PATCH',
      url: '/admin/clients/ext-ok',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify({ allowedProviders: ['email', 'google'] }),
    });
    expect(patch.statusCode).toBe(400);
  });

  it('PATCH несуществующего → 404', async () => {
    const app = await adminApp();
    const res = await app.inject({
      method: 'PATCH',
      url: '/admin/clients/нет',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify({ redirectUris: ['https://x.example/cb'] }),
    });
    expect(res.statusCode).toBe(404);
  });

  it('DELETE → 204, затем GET :id → 404', async () => {
    const app = await adminApp();
    await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify(internalClient),
    });
    const del = await app.inject({
      method: 'DELETE',
      url: '/admin/clients/internal-app',
      headers: AUTH,
    });
    expect(del.statusCode).toBe(204);
    const get = await app.inject({
      method: 'GET',
      url: '/admin/clients/internal-app',
      headers: AUTH,
    });
    expect(get.statusCode).toBe(404);
  });

  it('POST краткой формы { baseUrl } → 201, по умолчанию internal с email+google', async () => {
    const app = await adminApp();
    const res = await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify({ baseUrl: 'https://app.example.com' }),
    });
    expect(res.statusCode).toBe(201);
    expect(res.json()).toEqual({
      id: 'app.example.com',
      type: 'internal',
      redirectUris: ['https://app.example.com/api/auth/callback'],
      allowedProviders: ['email', 'google'],
      postLogoutRedirectUris: ['https://app.example.com/'],
    });
  });

  it('краткая форма с type external → 201, только email (google не добавляется)', async () => {
    const app = await adminApp();
    const res = await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify({ baseUrl: 'https://third.example', type: 'external' }),
    });
    expect(res.statusCode).toBe(201);
    expect(res.json().type).toBe('external');
    expect(res.json().allowedProviders).toEqual(['email']);
  });

  it('краткая форма с type external + google → 400', async () => {
    const app = await adminApp();
    const res = await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify({
        baseUrl: 'https://app.example.com',
        type: 'external',
        allowedProviders: ['google'],
      }),
    });
    expect(res.statusCode).toBe(400);
  });

  it('повторная регистрация того же baseUrl → 409', async () => {
    const app = await adminApp();
    const payload = JSON.stringify({ baseUrl: 'https://app.example.com' });
    await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload,
    });
    const dup = await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload,
    });
    expect(dup.statusCode).toBe(409);
  });

  it('краткая форма с http baseUrl (не localhost) → 400', async () => {
    const app = await adminApp();
    const res = await app.inject({
      method: 'POST',
      url: '/admin/clients',
      headers: { ...AUTH, ...JSON_HEADERS },
      payload: JSON.stringify({ baseUrl: 'http://app.example.com' }),
    });
    expect(res.statusCode).toBe(400);
  });

  it('без adminApiToken роут не смонтирован → GET /admin/clients → 404', async () => {
    const deps = await makeTestDeps({ clients: [] });
    const app = buildServer(deps);
    const res = await app.inject({
      method: 'GET',
      url: '/admin/clients',
      headers: AUTH,
    });
    expect(res.statusCode).toBe(404);
  });
});
