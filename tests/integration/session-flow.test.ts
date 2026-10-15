import { describe, it, expect } from 'vitest';
import { LoginService, type AuthorizationRequest } from '../../src/domain/login/login-service.js';
import { AuthorizationCodeService } from '../../src/domain/login/authorization-code-service.js';
import { InMemoryAuthorizationCodeStore } from '../../src/adapters/repository/in-memory-authorization-code-store.js';
import { InMemoryClientRegistry } from '../../src/adapters/repository/in-memory-client-registry.js';
import { IdentityService } from '../../src/domain/identity/identity-service.js';
import { InMemoryIdentityRepository } from '../../src/adapters/repository/in-memory-identity-repository.js';
import { SessionService } from '../../src/domain/sessions/session-service.js';
import { InMemorySessionStore } from '../../src/adapters/repository/in-memory-session-store.js';
import { InMemoryRefreshTokenStore } from '../../src/adapters/repository/in-memory-refresh-token-store.js';
import { TokenService } from '../../src/domain/tokens/token-service.js';
import { loadSigningKey } from '../../src/domain/tokens/signing-key.js';
import { computeS256Challenge } from '../../src/domain/login/pkce.js';
import { RefreshTokenReuseError } from '../../src/domain/sessions/errors.js';
import type { Client } from '../../src/domain/clients/client.js';
import type { ProviderIdentity } from '../../src/domain/identity/provider-identity.js';
import type { DeviceInfo } from '../../src/domain/sessions/device.js';
import { advanceableClock } from '../helpers/advanceable-clock.js';

const T0 = new Date('2026-07-01T00:00:00Z');
const VERIFIER = 'integration-session-verifier-1234567890-достаточно-длинный';
const CHALLENGE = computeS256Challenge(VERIFIER);
const REFRESH_TTL = 2592000; // 30 дней

const client: Client = {
  id: 'app1',
  type: 'external',
  redirectUris: ['https://app1/cb'],
  allowedProviders: ['email'],
};

const device: DeviceInfo = { userAgent: 'Mozilla/5.0', ip: '1.2.3.4' };

describe('интеграция: вход -> сессия -> ротация refresh -> reuse-detection', () => {
  it('сквозной путь до тройки токенов и обнаружение повторного использования', async () => {
    const clock = advanceableClock(T0);

    // Логин-граф: реестр клиентов, личности, коды авторизации.
    const repo = new InMemoryIdentityRepository(clock);
    const identity = new IdentityService(repo);
    const codes = new AuthorizationCodeService(new InMemoryAuthorizationCodeStore(), clock, 60);
    const login = new LoginService(new InMemoryClientRegistry([client]), identity, codes);

    // Сессионный граф: ключ подписи, токены, хранилища сессий и refresh.
    const key = await loadSigningKey({ autogenerate: true });
    const tokens = new TokenService(key, [key], clock, {
      issuer: 'https://auth',
      accessTtlSeconds: 900,
      idTtlSeconds: 900,
    });
    const refreshTokens = new InMemoryRefreshTokenStore();
    const sessions = new SessionService(
      new InMemorySessionStore(refreshTokens),
      refreshTokens,
      tokens,
      clock,
      { refreshTtlSeconds: REFRESH_TTL },
    );

    // 1. Валидация authorize-запроса с PKCE S256.
    const req: AuthorizationRequest = {
      clientId: 'app1',
      redirectUri: 'https://app1/cb',
      codeChallenge: CHALLENGE,
      codeChallengeMethod: 'S256',
      scope: 'openid',
      nonce: 'nonce-1',
    };
    const validated = await login.validateRequest(req);

    // 2. Аутентификация провайдером email -> authorization code.
    const pid: ProviderIdentity = {
      provider: 'email',
      subject: 'user@x.com',
      email: 'user@x.com',
      emailVerified: true,
      profile: { name: 'Аня' },
    };
    const { code: authCode } = await login.completeLogin(validated, pid);

    // 3. Обмен кода -> grant со снимком аутентификации.
    const grant = await codes.redeem({
      code: authCode,
      clientId: 'app1',
      redirectUri: 'https://app1/cb',
      codeVerifier: VERIFIER,
    });
    expect(grant.auth.provider).toBe('email');
    expect(grant.auth.email).toBe('user@x.com');
    expect(grant.auth.emailVerified).toBe(true);
    expect(grant.auth.name).toBe('Аня');

    // 4. Старт сессии -> тройка токенов + sessionId.
    const first = await sessions.start({
      userId: grant.userId,
      clientId: grant.clientId,
      provider: grant.auth.provider,
      profile: {
        email: grant.auth.email,
        emailVerified: grant.auth.emailVerified,
        name: grant.auth.name,
      },
      scope: grant.scope,
      device,
    });
    expect(first.accessToken).toBeTruthy();
    expect(first.idToken).toBeTruthy();
    expect(first.refreshToken).toBeTruthy();
    expect(first.sessionId).toBeTruthy();

    // 5. Ротация refresh -> новая пара, тот же sessionId.
    const t2 = await sessions.refresh(first.refreshToken, device);
    expect(t2.sessionId).toBe(first.sessionId);
    expect(t2.refreshToken).not.toBe(first.refreshToken);

    // 6. Одна живая сессия у пользователя.
    const active = await sessions.listForUser(grant.userId);
    expect(active).toHaveLength(1);
    expect(active[0]!.id).toBe(first.sessionId);

    // 7. Reuse-detection: цепочка обгоняет старый токен -> угон -> сессия отзывается.
    const t3 = await sessions.refresh(t2.refreshToken, device);
    expect(t3.sessionId).toBe(first.sessionId);

    // Обгон на 2 шага старее окна (60с) -> угон, а не легитимная гонка.
    clock.advance(61);
    await expect(sessions.refresh(first.refreshToken, device)).rejects.toBeInstanceOf(
      RefreshTokenReuseError,
    );

    const afterReuse = await sessions.listForUser(grant.userId);
    expect(afterReuse).toHaveLength(0);
  });
});
