import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import type { ClientType } from '../../../src/domain/clients/client.js';
import { makeTestDeps, TEST_CHALLENGE, TEST_VERIFIER } from './helpers.js';

const start = (userId: string, clientId = 'app', provider = 'email') => ({
  userId, clientId, provider, profile: {}, scope: 'openid', device: { ip: '127.0.0.1' },
});
const params = (userId = 'user', clientType: ClientType = 'external') => ({
  userId, clientId: 'app', clientType, redirectUri: 'https://app.example/cb',
  codeChallenge: TEST_CHALLENGE, scope: 'openid', auth: { provider: 'email', emailVerified: true },
});
const codeBody = (code: string) => ({ grant_type: 'authorization_code', code,
  client_id: 'app', redirect_uri: 'https://app.example/cb', code_verifier: TEST_VERIFIER });

describe('token endpoint trusted principals and live client policy', () => {
  it('more than 60 sessions behind one backend can refresh; abuse in one session spares the others', async () => {
    const deps = await makeTestDeps({ rateLimits: { token: { limit: 6000, windowSeconds: 900 } } });
    const app = buildServer(deps);
    try {
      const issued = await Promise.all(Array.from({ length: 65 }, (_, i) => deps.sessions.start(start(`u${i}`))));
      let firstSuccessor = '';
      for (const [i, t] of issued.entries()) {
        const res = await app.inject({ method: 'POST', url: '/oauth/token',
          payload: { grant_type: 'refresh_token', refresh_token: t.refreshToken } });
        expect(res.statusCode).toBe(200);
        if (i === 0) firstSuccessor = res.json().refresh_token;
      }
      // First session already used one request; rotations cannot reset its bucket.
      for (let i = 1; i < 60; i++) {
        const res = await app.inject({ method: 'POST', url: '/oauth/token',
          payload: { grant_type: 'refresh_token', refresh_token: firstSuccessor } });
        expect(res.statusCode).toBe(200);
      }
      const blocked = await app.inject({ method: 'POST', url: '/oauth/token',
        payload: { grant_type: 'refresh_token', refresh_token: firstSuccessor, client_id: 'invented' } });
      expect(blocked.statusCode).toBe(429);
      expect(blocked.headers['retry-after']).toBeDefined();
      const other = await app.inject({ method: 'POST', url: '/oauth/token',
        payload: { grant_type: 'refresh_token', refresh_token: issued[1]!.refreshToken } });
      expect(other.statusCode).toBe(200);
    } finally { await app.close(); }
  });

  it('many valid code exchanges share an IP without sharing the narrow principal budget', async () => {
    const deps = await makeTestDeps({ rateLimits: { token: { limit: 6000, windowSeconds: 900 } } });
    const app = buildServer(deps);
    try {
      for (let i = 0; i < 65; i++) {
        const code = await deps.codes.issue(params(`u${i}`));
        const res = await app.inject({ method: 'POST', url: '/oauth/token', payload: codeBody(code) });
        expect(res.statusCode).toBe(200);
      }
    } finally { await app.close(); }
  });

  it('отказ по лимиту пользователя не гасит код и не создаёт сессию', async () => {
    const deps = await makeTestDeps();
    let denyUser = true;
    const inner = deps.rateLimiter;
    deps.rateLimiter = {
      hit: (key, limit, windowSeconds) => key.startsWith('token-user:') && denyUser
        ? Promise.resolve({ allowed: false, remaining: 0, retryAfterSeconds: 30 })
        : inner.hit(key, limit, windowSeconds),
      close: () => inner.close(),
    };
    const app = buildServer(deps);
    try {
      const code = await deps.codes.issue(params('user'));
      const limited = await app.inject({ method: 'POST', url: '/oauth/token', payload: codeBody(code) });
      expect(limited.statusCode).toBe(429);
      expect(limited.headers['retry-after']).toBe('30');
      expect(await deps.sessions.listForUser('user')).toEqual([]);
      denyUser = false;
      expect((await app.inject({ method: 'POST', url: '/oauth/token', payload: codeBody(code) })).statusCode).toBe(200);
    } finally { await app.close(); }
  });

  it('untrusted XFF and arbitrary client IDs cannot evade the wide IP budget', async () => {
    const deps = await makeTestDeps({ trustProxy: 0,
      rateLimits: { token: { limit: 2, windowSeconds: 900 } } });
    const app = buildServer(deps);
    try {
      for (let i = 0; i < 3; i++) {
        const res = await app.inject({ method: 'POST', url: '/oauth/token',
          headers: { 'x-forwarded-for': `203.0.113.${i + 1}` },
          payload: { grant_type: 'refresh_token', refresh_token: `fake${i}`, client_id: `fake${i}` } });
        expect(res.statusCode).toBe(i < 2 ? 400 : 429);
      }
    } finally { await app.close(); }
  });

  it('DELETE client rejects outstanding code and refresh, including after the same ID is recreated', async () => {
    const deps = await makeTestDeps({ adminApiToken: 'test-admin' });
    const app = buildServer(deps);
    try {
      const client = (await deps.clients.findClient('app'))!;
      const code = await deps.codes.issue(params());
      const session = await deps.sessions.start(start('user'));
      const removed = await app.inject({ method: 'DELETE', url: '/admin/clients/app',
        headers: { authorization: 'Bearer test-admin' } });
      expect(removed.statusCode).toBe(204);
      const exchanged = await app.inject({ method: 'POST', url: '/oauth/token', payload: codeBody(code) });
      expect(exchanged.statusCode).toBe(400);
      expect(exchanged.json().error).toBe('invalid_grant');
      const body = { grant_type: 'refresh_token', refresh_token: session.refreshToken };
      expect((await app.inject({ method: 'POST', url: '/oauth/token', payload: body })).statusCode).toBe(400);
      await deps.adminClients!.create(client);
      expect((await app.inject({ method: 'POST', url: '/oauth/token', payload: body })).statusCode).toBe(400);
    } finally { await app.close(); }
  });

  it('registry checks reject code and refresh even if the registry changed outside the admin route', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    try {
      const code = await deps.codes.issue(params());
      const session = await deps.sessions.start(start('user'));
      await deps.adminClients!.delete('app');
      expect((await app.inject({ method: 'POST', url: '/oauth/token', payload: codeBody(code) })).statusCode).toBe(400);
      expect((await app.inject({ method: 'POST', url: '/oauth/token', payload: {
        grant_type: 'refresh_token', refresh_token: session.refreshToken,
        client_id: 'another-existing-client',
      } })).statusCode).toBe(400);
    } finally { await app.close(); }
  });

  it('provider policy changes reject previous grants; admin patch revokes only incompatible sessions', async () => {
    const deps = await makeTestDeps({ adminApiToken: 'test-admin', clients: [{ id: 'app', type: 'internal',
      redirectUris: ['https://app.example/cb'], allowedProviders: ['email', 'google'] }] });
    const app = buildServer(deps);
    try {
      const code = await deps.codes.issue(params('user', 'internal'));
      const email = await deps.sessions.start(start('user'));
      const google = await deps.sessions.start(start('user', 'app', 'google'));
      const patched = await app.inject({ method: 'PATCH', url: '/admin/clients/app',
        headers: { authorization: 'Bearer test-admin' }, payload: { allowedProviders: ['google'] } });
      expect(patched.statusCode).toBe(200);
      expect((await app.inject({ method: 'POST', url: '/oauth/token', payload: codeBody(code) })).statusCode).toBe(400);
      const refresh = (raw: string) => app.inject({ method: 'POST', url: '/oauth/token', payload: {
        grant_type: 'refresh_token', refresh_token: raw,
      } });
      expect((await refresh(email.refreshToken)).statusCode).toBe(400);
      expect((await refresh(google.refreshToken)).statusCode).toBe(200);
      await deps.adminClients!.update('app', { allowedProviders: ['email', 'google'] });
      expect((await refresh(email.refreshToken)).statusCode).toBe(400);
    } finally { await app.close(); }
  });

  it('R09: смена типа клиента отзывает его сессии и гасит невыданные коды; PATCH без смены типа их не трогает', async () => {
    for (const [from, to] of [['internal', 'external'], ['external', 'internal']] as const) {
      const deps = await makeTestDeps({ adminApiToken: 'test-admin', clients: [{ id: 'app', type: from,
        redirectUris: ['https://app.example/cb'], allowedProviders: ['email'] }] });
      const app = buildServer(deps);
      try {
        const patch = (payload: object) => app.inject({ method: 'PATCH', url: '/admin/clients/app',
          headers: { authorization: 'Bearer test-admin' }, payload });
        const refresh = (raw: string) => app.inject({ method: 'POST', url: '/oauth/token', payload: {
          grant_type: 'refresh_token', refresh_token: raw } });
        const kept = await deps.sessions.start(start('user'));
        expect((await patch({ type: from, redirectUris: ['https://app.example/cb'] })).statusCode).toBe(200);
        const keptNext = await refresh(kept.refreshToken);
        expect(keptNext.statusCode).toBe(200);

        const code = await deps.codes.issue(params('user', from));
        expect((await patch({ type: to })).statusCode).toBe(200);
        expect((await app.inject({ method: 'POST', url: '/oauth/token', payload: codeBody(code) })).statusCode).toBe(400);
        expect((await refresh(keptNext.json().refresh_token)).statusCode).toBe(400);
      } finally { await app.close(); }
    }
  });

  it('current provider and redirect policy is enforced for grants without relying on revocation', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    try {
      const code = await deps.codes.issue(params());
      const session = await deps.sessions.start(start('user'));
      await deps.adminClients!.update('app', { allowedProviders: ['google'] });
      expect((await app.inject({ method: 'POST', url: '/oauth/token', payload: codeBody(code) })).statusCode).toBe(400);
      expect((await app.inject({ method: 'POST', url: '/oauth/token', payload: {
        grant_type: 'refresh_token', refresh_token: session.refreshToken,
      } })).statusCode).toBe(400);
      await deps.adminClients!.update('app', { allowedProviders: ['email'], redirectUris: ['https://app.example/new'] });
      const oldRedirectCode = await deps.codes.issue(params());
      expect((await app.inject({ method: 'POST', url: '/oauth/token', payload: codeBody(oldRedirectCode) })).statusCode).toBe(400);
    } finally { await app.close(); }
  });
});
