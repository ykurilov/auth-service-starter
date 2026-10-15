import { describe, it, expect } from 'vitest';
import { SessionService } from '../../../src/domain/sessions/session-service.js';
import { InMemorySessionStore } from '../../../src/adapters/repository/in-memory-session-store.js';
import { InMemoryRefreshTokenStore } from '../../../src/adapters/repository/in-memory-refresh-token-store.js';
import { TokenService } from '../../../src/domain/tokens/token-service.js';
import { loadSigningKey } from '../../../src/domain/tokens/signing-key.js';
import { sha256Hex } from '../../../src/domain/shared/hash.js';
import { advanceableClock } from '../../helpers/advanceable-clock.js';

const REFRESH_TTL = 2592000; // 30 дней

async function setup() {
  const key = await loadSigningKey({ autogenerate: true });
  const clock = advanceableClock(new Date('2026-07-01T00:00:00Z'));
  const tokens = new TokenService(key, [key], clock, {
    issuer: 'https://auth',
    accessTtlSeconds: 900,
    idTtlSeconds: 900,
  });
  const refresh = new InMemoryRefreshTokenStore();
  const sessions = new InMemorySessionStore(refresh);
  const service = new SessionService(sessions, refresh, tokens, clock, {
    refreshTtlSeconds: REFRESH_TTL,
  });
  return { service, sessions, refresh, clock, key };
}

const startParams = {
  userId: 'u1',
  clientId: 'app',
  provider: 'email',
  profile: { email: 'a@b.co', emailVerified: true, name: 'Аня' },
  device: { userAgent: 'Mozilla/5.0', ip: '1.2.3.4' },
  scope: 'openid profile email',
};

describe('SessionService.start', () => {
  it('создаёт сессию и возвращает тройку токенов', async () => {
    const { service, sessions } = await setup();
    const out = await service.start(startParams);
    expect(out.accessToken).toBeTruthy();
    expect(out.idToken).toBeTruthy();
    expect(out.refreshToken).toBeTruthy();
    expect(out.expiresIn).toBe(900);
    expect(out.sessionId).toBeTruthy();
    const s = await sessions.findById(out.sessionId);
    expect(s!.userId).toBe('u1');
    expect(s!.provider).toBe('email');
    expect(s!.expiresAt).toEqual(new Date('2026-07-31T00:00:00Z')); // now + 30д
    expect(s!.revokedAt).toBeNull();
  });

  it('сохраняет нормализованный scope в сессии', async () => {
    const { service, sessions } = await setup();
    const out = await service.start({ ...startParams, scope: 'email openid' });
    const s = await sessions.findById(out.sessionId);
    expect(s!.scope).toBe('openid email');
  });

  it('scope=openid → в id_token нет email и name', async () => {
    const { service, key, clock } = await setup();
    const out = await service.start({ ...startParams, scope: 'openid' });
    const { jwtVerify } = await import('jose');
    const id = (await jwtVerify(out.idToken, key.publicKey, { currentDate: clock.now() })).payload;
    expect(id.email).toBeUndefined();
    expect(id.name).toBeUndefined();
    expect(id.auth_provider).toBe('email');
  });

  it('refresh-токен сохранён только как хеш, как голова цепочки', async () => {
    const { service, refresh } = await setup();
    const out = await service.start(startParams);
    const rec = await refresh.findByHash(sha256Hex(out.refreshToken));
    expect(rec).not.toBeNull();
    expect(rec!.previousTokenId).toBeNull();
    expect(rec!.replacedById).toBeNull();
    expect(rec!.consumedAt).toBeNull();
  });

  it('id_token несёт провайдера и профиль, access — пустые роли', async () => {
    const { service, key, clock } = await setup();
    const out = await service.start(startParams);
    const { jwtVerify } = await import('jose');
    const currentDate = clock.now();
    const id = (await jwtVerify(out.idToken, key.publicKey, { currentDate })).payload;
    expect(id.auth_provider).toBe('email');
    expect(id.email).toBe('a@b.co');
    expect(id.email_verified).toBe(true);
    const at = (await jwtVerify(out.accessToken, key.publicKey, { currentDate })).payload;
    expect(at.roles).toEqual([]);
  });
});
