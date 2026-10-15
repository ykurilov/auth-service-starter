import { describe, it, expect } from 'vitest';
import { LoginService, type AuthorizationRequest } from '../../src/domain/login/login-service.js';
import { AuthorizationCodeService } from '../../src/domain/login/authorization-code-service.js';
import { InMemoryAuthorizationCodeStore } from '../../src/adapters/repository/in-memory-authorization-code-store.js';
import { InMemoryClientRegistry } from '../../src/adapters/repository/in-memory-client-registry.js';
import { IdentityService } from '../../src/domain/identity/identity-service.js';
import { InMemoryIdentityRepository } from '../../src/adapters/repository/in-memory-identity-repository.js';
import { EmailCodeProvider } from '../../src/domain/email-login/email-code-provider.js';
import { InMemoryLoginChallengeStore } from '../../src/adapters/repository/in-memory-login-challenge-store.js';
import { FakeMailer } from '../../src/adapters/mail/fake-mailer.js';
import { computeS256Challenge } from '../../src/domain/login/pkce.js';
import type { Client } from '../../src/domain/clients/client.js';
import { fakeClock } from '../helpers/fake-clock.js';

const T0 = new Date('2026-07-01T00:00:00Z');
const VERIFIER = 'integration-verifier-1234567890-достаточно-длинный';
const CHALLENGE = computeS256Challenge(VERIFIER);

const client: Client = {
  id: 'app1',
  type: 'external',
  redirectUris: ['https://app1/cb'],
  allowedProviders: ['email'],
};

describe('интеграция: сквозной вход по email-коду', () => {
  it('authorize -> код на почту -> вход -> authorization code -> обмен -> grant того же пользователя', async () => {
    const clock = fakeClock(T0);
    const repo = new InMemoryIdentityRepository(clock);
    const identity = new IdentityService(repo);
    const codes = new AuthorizationCodeService(new InMemoryAuthorizationCodeStore(), clock, 60);
    const login = new LoginService(new InMemoryClientRegistry([client]), identity, codes);

    const mailer = new FakeMailer();
    const codeProvider = new EmailCodeProvider(new InMemoryLoginChallengeStore(), mailer, clock, {
      appName: 'Auth Service',
      codeTtlMinutes: 15,
      generateCode: () => 'CODE99',
    });

    const req: AuthorizationRequest = {
      clientId: 'app1',
      redirectUri: 'https://app1/cb',
      codeChallenge: CHALLENGE,
      codeChallengeMethod: 'S256',
      scope: 'openid',
      nonce: 'nonce-1',
    };

    const validated = await login.validateRequest(req);

    const started = await codeProvider.start({ email: 'user@x.com', binding: 'b' });
    expect(mailer.last?.text).toContain('CODE99');

    const pid = await codeProvider.verify({ handle: started.handle, binding: 'b', code: 'CODE99' });
    expect(pid.emailVerified).toBe(true);

    const { code: authCode } = await login.completeLogin(validated, pid);

    const grant = await codes.redeem({
      code: authCode,
      clientId: 'app1',
      redirectUri: 'https://app1/cb',
      codeVerifier: VERIFIER,
    });

    expect(grant.nonce).toBe('nonce-1');
    expect(grant.scope).toBe('openid');

    const started2 = await codeProvider.start({ email: 'user@x.com', binding: 'b' });
    const pid2 = await codeProvider.verify({ handle: started2.handle, binding: 'b', code: 'CODE99' });
    const again = await identity.resolveLogin(pid2);
    expect(again.user.id).toBe(grant.userId);
    expect(again.createdUser).toBe(false);
  });
});
