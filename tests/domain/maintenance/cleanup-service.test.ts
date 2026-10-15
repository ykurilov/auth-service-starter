import { describe, it, expect } from 'vitest';
import { CleanupService } from '../../../src/domain/maintenance/cleanup-service.js';
import { InMemoryAuthorizationCodeStore } from '../../../src/adapters/repository/in-memory-authorization-code-store.js';
import { InMemoryEmailSecretStore } from '../../../src/adapters/repository/in-memory-email-secret-store.js';
import { InMemorySessionStore } from '../../../src/adapters/repository/in-memory-session-store.js';
import { InMemoryRefreshTokenStore } from '../../../src/adapters/repository/in-memory-refresh-token-store.js';
import { InMemorySsoSessionStore } from '../../../src/adapters/repository/in-memory-sso-session-store.js';
import { fakeClock } from '../../helpers/fake-clock.js';
import type { AuthorizationCodeRecord } from '../../../src/domain/login/authorization-code.js';
import type { EmailSecretRecord } from '../../../src/domain/email-secret/email-secret.js';
import type { Session } from '../../../src/domain/sessions/session.js';
import type { SsoSession } from '../../../src/domain/sso/sso-session.js';

const NOW = new Date('2026-07-02T00:00:00Z');
const DAY_MS = 24 * 3600 * 1000;

function makeCode(over: Partial<AuthorizationCodeRecord> = {}): AuthorizationCodeRecord {
  return {
    id: over.id ?? 'code-1',
    codeHash: over.codeHash ?? `hash-${over.id ?? '1'}`,
    clientId: 'app1',
    clientType: 'internal',
    userId: 'u1',
    redirectUri: 'https://app1/cb',
    codeChallenge: 'chal',
    scope: 'openid',
    auth: { provider: 'email' },
    expiresAt: over.expiresAt ?? NOW,
    consumedAt: over.consumedAt ?? null,
  };
}

function makeSecret(over: Partial<EmailSecretRecord> = {}): EmailSecretRecord {
  return {
    id: over.id ?? 'secret-1',
    purpose: 'email-code-login',
    email: 'a@b.com',
    secretHash: over.secretHash ?? `hash-${over.id ?? '1'}`,
    expiresAt: over.expiresAt ?? NOW,
    consumedAt: over.consumedAt ?? null,
  };
}

function makeSession(over: Partial<Session> = {}): Session {
  return {
    id: over.id ?? 'session-1',
    userId: 'u1',
    clientId: 'app1',
    provider: 'email',
    profile: {},
    scope: 'openid',
    deviceFingerprint: 'fp',
    ipHash: 'ip',
    createdAt: NOW,
    lastUsedAt: NOW,
    expiresAt: over.expiresAt ?? NOW,
    revokedAt: over.revokedAt ?? null,
    ...over,
  };
}

function makeSsoSession(over: Partial<SsoSession> = {}): SsoSession {
  return {
    id: over.id ?? 'sso-1',
    userId: 'u1',
    auth: { provider: 'email' },
    tokenHash: over.tokenHash ?? `hash-${over.id ?? '1'}`,
    createdAt: NOW,
    lastUsedAt: NOW,
    expiresAt: over.expiresAt ?? NOW,
    revokedAt: over.revokedAt ?? null,
    ...over,
  };
}

describe('CleanupService', () => {
  it('runOnce чистит коды/email-секреты по before=now, а сессии/sso — по before=now-30д', async () => {
    const clock = fakeClock(NOW);
    const codes = new InMemoryAuthorizationCodeStore();
    const emailSecrets = new InMemoryEmailSecretStore();
    const refreshTokens = new InMemoryRefreshTokenStore();
    const sessions = new InMemorySessionStore(refreshTokens);
    const sso = new InMemorySsoSessionStore();

    // Коды: один истёкший (до now), один живой (после now).
    await codes.save(makeCode({ id: 'expired-code', codeHash: 'h-expired-code', expiresAt: new Date(NOW.getTime() - 1000) }));
    await codes.save(makeCode({ id: 'live-code', codeHash: 'h-live-code', expiresAt: new Date(NOW.getTime() + 1000) }));

    // Email-секреты: аналогично.
    await emailSecrets.save(makeSecret({ id: 'expired-secret', secretHash: 'h-expired-secret', expiresAt: new Date(NOW.getTime() - 1000) }));
    await emailSecrets.save(makeSecret({ id: 'live-secret', secretHash: 'h-live-secret', expiresAt: new Date(NOW.getTime() + 1000) }));

    // Сессии: истекла 31 день назад (должна уйти), истекла вчера (должна остаться —
    // ретеншн 30 дней ещё не прошёл).
    await sessions.save(makeSession({ id: 'session-31d-ago', expiresAt: new Date(NOW.getTime() - 31 * DAY_MS) }));
    await sessions.save(makeSession({ id: 'session-yesterday', expiresAt: new Date(NOW.getTime() - DAY_MS) }));

    // SSO-сессии: то же правило ретеншна.
    await sso.save(makeSsoSession({ id: 'sso-31d-ago', tokenHash: 'h-sso-31d', expiresAt: new Date(NOW.getTime() - 31 * DAY_MS) }));
    await sso.save(makeSsoSession({ id: 'sso-yesterday', tokenHash: 'h-sso-yesterday', expiresAt: new Date(NOW.getTime() - DAY_MS) }));

    const service = new CleanupService(codes, emailSecrets, sessions, sso, clock);
    const counts = await service.runOnce();

    expect(counts).toEqual({ codes: 1, emailSecrets: 1, sessions: 1, ssoSessions: 1, shortLived: 0 });

    // Коды/секреты: живые всё ещё находятся обычным поиском (значит не удалены);
    // истёкшие подтверждённо удалены физически — второй прогон deleteExpired
    // с запасом по времени находит только оставшийся живой код/секрет.
    expect(await codes.findActiveByHash('h-live-code', new Date(NOW.getTime() + 500))).not.toBeNull();
    expect(await emailSecrets.findActive('email-code-login', 'a@b.com', new Date(NOW.getTime() + 500))).not.toBeNull();
    expect(await codes.deleteExpired(new Date(NOW.getTime() + 2000))).toBe(1); // остался только live-code
    expect(await emailSecrets.deleteExpired(new Date(NOW.getTime() + 2000))).toBe(1); // остался только live-secret

    // Сессии: 31-дневная удалена, вчерашняя всё ещё хранится (retention).
    expect(await sessions.findById('session-31d-ago')).toBeNull();
    expect(await sessions.findById('session-yesterday')).not.toBeNull();

    // SSO: то же самое.
    expect(await sso.findByHash('h-sso-31d')).toBeNull();
    expect(await sso.findByHash('h-sso-yesterday')).not.toBeNull();
  });
});
