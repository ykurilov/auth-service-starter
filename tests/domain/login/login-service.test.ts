import { describe, it, expect } from 'vitest';
import { LoginService, type AuthorizationRequest } from '../../../src/domain/login/login-service.js';
import { AuthorizationCodeService } from '../../../src/domain/login/authorization-code-service.js';
import { InMemoryAuthorizationCodeStore } from '../../../src/adapters/repository/in-memory-authorization-code-store.js';
import { InMemoryClientRegistry } from '../../../src/adapters/repository/in-memory-client-registry.js';
import { IdentityService } from '../../../src/domain/identity/identity-service.js';
import { InMemoryIdentityRepository } from '../../../src/adapters/repository/in-memory-identity-repository.js';
import { computeS256Challenge } from '../../../src/domain/login/pkce.js';
import {
  InvalidClientError,
  InvalidRedirectUriError,
  UnsupportedPkceError,
  ProviderNotAllowedError,
} from '../../../src/domain/login/errors.js';
import type { Client } from '../../../src/domain/clients/client.js';
import type { ProviderIdentity } from '../../../src/domain/identity/provider-identity.js';
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
  const repo = new InMemoryIdentityRepository(clock);
  const identity = new IdentityService(repo);
  const codes = new AuthorizationCodeService(new InMemoryAuthorizationCodeStore(), clock, 60);
  const login = new LoginService(clients, identity, codes);
  return { login, codes };
}

const req: AuthorizationRequest = {
  clientId: 'app1',
  redirectUri: 'https://app1/cb',
  codeChallenge: CHALLENGE,
  codeChallengeMethod: 'S256',
  scope: 'openid',
  nonce: 'n1',
};

const emailPid: ProviderIdentity = {
  provider: 'email',
  subject: 'code:a@b.com',
  email: 'a@b.com',
  emailVerified: true,
  profile: {},
};

describe('LoginService.validateRequest', () => {
  it('пропускает корректный запрос и возвращает клиента', async () => {
    const { login } = make();
    const v = await login.validateRequest(req);
    expect(v.client.id).toBe('app1');
  });

  it('неизвестный клиент -> InvalidClientError', async () => {
    const { login } = make();
    await expect(login.validateRequest({ ...req, clientId: 'nope' })).rejects.toBeInstanceOf(InvalidClientError);
  });

  it('redirect_uri вне allowlist -> InvalidRedirectUriError', async () => {
    const { login } = make();
    await expect(login.validateRequest({ ...req, redirectUri: 'https://evil/cb' })).rejects.toBeInstanceOf(InvalidRedirectUriError);
  });

  it('метод PKCE не S256 -> UnsupportedPkceError', async () => {
    const { login } = make();
    await expect(login.validateRequest({ ...req, codeChallengeMethod: 'plain' })).rejects.toBeInstanceOf(UnsupportedPkceError);
  });

  it('пустой code_challenge -> UnsupportedPkceError', async () => {
    const { login } = make();
    await expect(login.validateRequest({ ...req, codeChallenge: '' })).rejects.toBeInstanceOf(UnsupportedPkceError);
  });
});

describe('LoginService.completeLogin', () => {
  it('разрешённый провайдер: заводит пользователя и выпускает рабочий код', async () => {
    const { login, codes } = make();
    const v = await login.validateRequest(req);
    const result = await login.completeLogin(v, emailPid);
    expect(result.userId).toBeTruthy();
    expect(result.auth.provider).toBe('email');
    const grant = await codes.redeem({
      code: result.code,
      clientId: 'app1',
      redirectUri: 'https://app1/cb',
      codeVerifier: 'verifier-1234567890-достаточно',
    });
    expect(grant.clientId).toBe('app1');
    expect(grant.scope).toBe('openid');
    expect(grant.nonce).toBe('n1');
    expect(grant.userId).toBe(result.userId);
  });

  it('провайдер не в allowedProviders -> ProviderNotAllowedError', async () => {
    const { login } = make();
    const v = await login.validateRequest(req);
    const googlePid: ProviderIdentity = { provider: 'google', subject: 'g1', email: 'a@b.com', emailVerified: true, profile: {} };
    await expect(login.completeLogin(v, googlePid)).rejects.toBeInstanceOf(ProviderNotAllowedError);
  });
});

describe('LoginService.completeLogin: снимок адреса из базы (R01)', () => {
  it('адрес занят другим пользователем → в коде и снимке прежний подтверждённый адрес', async () => {
    const { login, codes } = make();
    const googleClient = { ...client, allowedProviders: ['email', 'google'] };
    const validated = { client: googleClient, request: req };
    await login.completeLogin(validated, { ...emailPid, subject: 'code:v@corp.example', email: 'v@corp.example' });
    const first = await login.completeLogin(validated, {
      provider: 'google', subject: 'g-a', email: 'a@corp.example', emailVerified: true, profile: {},
    });
    const again = await login.completeLogin(validated, {
      provider: 'google', subject: 'g-a', email: 'v@corp.example', emailVerified: true, profile: {},
    });
    expect(again.userId).toBe(first.userId);
    expect(again.auth).toMatchObject({ email: 'a@corp.example', emailVerified: true });
    const grant = await codes.redeem({
      code: again.code, clientId: 'app1', redirectUri: 'https://app1/cb', codeVerifier: 'verifier-1234567890-достаточно',
    });
    expect(grant.auth).toMatchObject({ email: 'a@corp.example', emailVerified: true });
  });
});
