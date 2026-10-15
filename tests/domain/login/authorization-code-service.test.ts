import { describe, it, expect } from 'vitest';
import { AuthorizationCodeService } from '../../../src/domain/login/authorization-code-service.js';
import { InMemoryAuthorizationCodeStore } from '../../../src/adapters/repository/in-memory-authorization-code-store.js';
import { computeS256Challenge } from '../../../src/domain/login/pkce.js';
import { InvalidGrantError } from '../../../src/domain/login/errors.js';
import { fakeClock } from '../../helpers/fake-clock.js';

const T0 = new Date('2026-07-01T00:00:00Z');
const VERIFIER = 'verifier-строка-достаточной-длины-1234567890';
const CHALLENGE = computeS256Challenge(VERIFIER);

function make(ttl = 60, now: Date = T0) {
  const store = new InMemoryAuthorizationCodeStore();
  const service = new AuthorizationCodeService(store, fakeClock(now), ttl);
  return { store, service };
}

const issueParams = {
  clientId: 'app1',
  userId: 'u1',
  redirectUri: 'https://app1/cb',
  codeChallenge: CHALLENGE,
  scope: 'openid profile',
  nonce: 'n-123',
  auth: { provider: 'email', emailVerified: false },
};

const redeem = (code: string) => ({
  code,
  clientId: 'app1',
  redirectUri: 'https://app1/cb',
  codeVerifier: VERIFIER,
});

describe('AuthorizationCodeService', () => {
  it('issue возвращает непустой код, redeem с верным verifier даёт grant', async () => {
    const { service } = make();
    const code = await service.issue(issueParams);
    expect(code.length).toBeGreaterThan(0);
    const grant = await service.redeem(redeem(code));
    expect(grant).toEqual({
      userId: 'u1',
      clientId: 'app1',
      scope: 'openid profile',
      nonce: 'n-123',
      auth: { provider: 'email', emailVerified: false },
    });
  });

  it('redeem возвращает снимок аутентификации', async () => {
    const { service } = make();
    const code = await service.issue({
      ...issueParams,
      auth: { provider: 'email', email: 'a@b.co', emailVerified: true, name: 'Аня' },
    });
    const grant = await service.redeem(redeem(code));
    expect(grant.auth).toEqual({ provider: 'email', email: 'a@b.co', emailVerified: true, name: 'Аня' });
  });

  it('код одноразовый: повторный redeem бросает InvalidGrantError', async () => {
    const { service } = make();
    const code = await service.issue(issueParams);
    await service.redeem(redeem(code));
    await expect(service.redeem(redeem(code))).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('неверный PKCE-verifier -> InvalidGrantError', async () => {
    const { service } = make();
    const code = await service.issue(issueParams);
    await expect(
      service.redeem({ ...redeem(code), codeVerifier: 'не-тот-verifier' }),
    ).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('чужой clientId -> InvalidGrantError', async () => {
    const { service } = make();
    const code = await service.issue(issueParams);
    await expect(
      service.redeem({ ...redeem(code), clientId: 'app2' }),
    ).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('другой redirectUri -> InvalidGrantError', async () => {
    const { service } = make();
    const code = await service.issue(issueParams);
    await expect(
      service.redeem({ ...redeem(code), redirectUri: 'https://app1/other' }),
    ).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('несуществующий код -> InvalidGrantError', async () => {
    const { service } = make();
    await expect(service.redeem(redeem('нет-такого-кода'))).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('просроченный код -> InvalidGrantError', async () => {
    const store = new InMemoryAuthorizationCodeStore();
    const issuer = new AuthorizationCodeService(store, fakeClock(T0), 60);
    const code = await issuer.issue(issueParams);
    const later = new AuthorizationCodeService(store, fakeClock(new Date('2026-07-01T00:05:00Z')), 60);
    await expect(later.redeem(redeem(code))).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('в хранилище нет сырого кода — только его SHA-256', async () => {
    const { service } = make();
    const code = await service.issue(issueParams);
    await expect(service.redeem(redeem('phony'))).rejects.toBeInstanceOf(InvalidGrantError);
    expect(await service.redeem(redeem(code))).toBeTruthy();
  });
});
