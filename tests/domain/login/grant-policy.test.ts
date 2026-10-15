import { describe, it, expect } from 'vitest';
import { grantFitsClient } from '../../../src/domain/login/grant-policy.js';
import type { Client } from '../../../src/domain/clients/client.js';
import type { AuthorizationGrant } from '../../../src/domain/login/authorization-code.js';

const client: Client = { id: 'app', type: 'internal', redirectUris: ['https://app.example/cb'], allowedProviders: ['email'] };
const grant: AuthorizationGrant = { userId: 'u', clientId: 'app', clientType: 'internal', scope: 'openid',
  auth: { provider: 'email' } };
const cb = 'https://app.example/cb';

describe('grantFitsClient', () => {
  it('принимает код, выданный по текущим правилам клиента', () => {
    expect(grantFitsClient(client, grant, cb)).toBe(true);
  });

  it('отклоняет код, если тип клиента изменился после решения о согласии', () => {
    expect(grantFitsClient({ ...client, type: 'external' }, grant, cb)).toBe(false);
    expect(grantFitsClient(client, { ...grant, clientType: 'external' }, cb)).toBe(false);
  });

  it('отклоняет удалённого клиента, запрещённого провайдера и незарегистрированный адрес', () => {
    expect(grantFitsClient(null, grant, cb)).toBe(false);
    expect(grantFitsClient({ ...client, allowedProviders: ['google'] }, grant, cb)).toBe(false);
    expect(grantFitsClient(client, grant, 'https://evil.example/cb')).toBe(false);
  });
});
