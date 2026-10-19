import { describe, it, expect } from 'vitest';
import { LoginService, type AuthorizationRequest } from '../../../src/domain/login/login-service.js';
import { AuthorizationCodeService } from '../../../src/domain/login/authorization-code-service.js';
import { InMemoryAuthorizationCodeStore } from '../../../src/adapters/repository/in-memory-authorization-code-store.js';
import { InMemoryClientRegistry } from '../../../src/adapters/repository/in-memory-client-registry.js';
import { IdentityService } from '../../../src/domain/identity/identity-service.js';
import { InMemoryIdentityRepository } from '../../../src/adapters/repository/in-memory-identity-repository.js';
import { computeS256Challenge } from '../../../src/domain/login/pkce.js';
import { ProviderNotAllowedError } from '../../../src/domain/login/errors.js';
import type { Client } from '../../../src/domain/clients/client.js';
import type { AuthSnapshot } from '../../../src/domain/login/authorization-code.js';
import { fakeClock } from '../../helpers/fake-clock.js';

const T0 = new Date('2026-07-01T00:00:00Z');
const CHALLENGE = computeS256Challenge('verifier-1234567890-достаточно');

const client: Client = {
  id: 'app1',
  type: 'external',
  redirectUris: ['https://app1/cb'],
  allowedProviders: ['email'],
};

function make() {
  const clock = fakeClock(T0);
  const clients = new InMemoryClientRegistry([client]);
  const store = new InMemoryAuthorizationCodeStore();
  const repo = new InMemoryIdentityRepository(clock);
  const identity = new IdentityService(repo);
  const codes = new AuthorizationCodeService(store, clock, 60);
  const login = new LoginService(clients, identity, codes);
  return { login, codes, store };
}

const req: AuthorizationRequest = {
  clientId: 'app1',
  redirectUri: 'https://app1/cb',
  codeChallenge: CHALLENGE,
  codeChallengeMethod: 'S256',
  scope: 'openid',
  nonce: 'n1',
};

const auth: AuthSnapshot = {
  provider: 'email',
  email: 'a@b.com',
  emailVerified: true,
  name: 'Alice',
};

describe('LoginService.completeSsoLogin', () => {
  it('разрешённый провайдер: выпускает рабочий код с userId, auth и цепочкой SSO в сторе', async () => {
    const { login, codes } = make();
    const v = await login.validateRequest(req);
    const code = await login.completeSsoLogin(v, { userId: 'user-42', auth, chainId: 'chain-1' });
    expect(typeof code).toBe('string');
    expect(code.length).toBeGreaterThan(0);
    const grant = await codes.redeem({
      code,
      clientId: 'app1',
      redirectUri: 'https://app1/cb',
      codeVerifier: 'verifier-1234567890-достаточно',
    });
    expect(grant.userId).toBe('user-42');
    expect(grant.auth).toEqual(auth);
    expect(grant.ssoChainId).toBe('chain-1');
  });

  it('провайдер не в allowedProviders -> ProviderNotAllowedError', async () => {
    const { login } = make();
    const v = await login.validateRequest(req);
    await expect(
      login.completeSsoLogin(v, { userId: 'user-42', auth: { ...auth, provider: 'google' }, chainId: 'chain-1' }),
    ).rejects.toBeInstanceOf(ProviderNotAllowedError);
  });
});
