import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { LoginService } from '../../../src/domain/login/login-service.js';
import { IdentityService } from '../../../src/domain/identity/identity-service.js';
import type { Client, ClientRegistry } from '../../../src/domain/clients/client.js';
import { makeTestDeps, loginWithCode, startCodeLogin, authorizeForm, TEST_VERIFIER, FORM_HEADERS } from './helpers.js';

// T02: вход, решённый по снимку клиента, не привязывается к регистрации,
// созданной заново с тем же id. Здесь — хранилища в памяти; на PostgreSQL —
// tests/integration/pg-real-client-admin.test.ts.
const ADMIN = 'admin-token';
const client: Client = {
  id: 'app', type: 'internal', redirectUris: ['https://app.example/cb'], allowedProviders: ['email'],
};

describe('T02: повторное создание клиента между решением о входе и записью кода', () => {
  it('код, выданный по снимку удалённой регистрации, новая регистрация не обменивает', async () => {
    const deps = await makeTestDeps({ clients: [client], adminApiToken: ADMIN });
    const app = buildServer(deps);
    const admin = (method: 'POST' | 'DELETE', url: string, payload?: object) =>
      app.inject({ method, url, headers: { authorization: `Bearer ${ADMIN}` }, ...(payload ? { payload } : {}) });
    // Вход прочитал клиента (снимок старой регистрации), после чего администратор
    // удалил его и создал заново с теми же настройками.
    let armed = false;
    const recreating: ClientRegistry = {
      async findClient(id) {
        const snapshot = await deps.clients.findClient(id);
        if (armed) {
          armed = false;
          expect((await admin('DELETE', `/admin/clients/${id}`)).statusCode).toBe(204);
          expect((await admin('POST', '/admin/clients', client)).statusCode).toBe(201);
        }
        return snapshot;
      },
    };
    deps.login = new LoginService(recreating, new IdentityService(deps.repo), deps.codes);
    try {
      const exchange = (code: string) => app.inject({
        method: 'POST', url: '/oauth/token', headers: FORM_HEADERS,
        payload: new URLSearchParams({ grant_type: 'authorization_code', code, client_id: 'app',
          redirect_uri: 'https://app.example/cb', code_verifier: TEST_VERIFIER }).toString(),
      });
      // Попытка начата по прежней регистрации; клиент пересоздаётся при
      // проверке кода, сразу после того как вход прочитал его снимок.
      const challenge = await startCodeLogin(app, 'user@x.com');
      armed = true;
      const verified = await app.inject({
        method: 'POST', url: '/authorize/code/verify', headers: FORM_HEADERS,
        payload: authorizeForm({ challenge, code: 'CODE55' }),
      });
      expect(armed).toBe(false);
      const late = new URL(verified.headers['location'] as string).searchParams.get('code')!;
      const res = await exchange(late);
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe('invalid_grant');
      // Вход, решённый уже по новой регистрации, работает.
      expect((await exchange(await loginWithCode(app))).statusCode).toBe(200);
    } finally {
      await app.close();
    }
  });

  it('Admin API не показывает идентификатор регистрации', async () => {
    const deps = await makeTestDeps({ clients: [client], adminApiToken: ADMIN });
    const app = buildServer(deps);
    try {
      const auth = { authorization: `Bearer ${ADMIN}` };
      const list = await app.inject({ method: 'GET', url: '/admin/clients', headers: auth });
      expect(list.json()).toEqual([client]);
      const one = await app.inject({ method: 'GET', url: '/admin/clients/app', headers: auth });
      expect(one.json()).toEqual(client);
      const patched = await app.inject({ method: 'PATCH', url: '/admin/clients/app', headers: auth,
        payload: { redirectUris: ['https://app.example/cb2'] } });
      expect(patched.json()).not.toHaveProperty('registrationId');
    } finally {
      await app.close();
    }
  });
});
