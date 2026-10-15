import { describe, it, expect } from 'vitest';
import { SsoSessionService } from '../../../src/domain/sso/sso-session-service.js';
import { InMemorySsoSessionStore } from '../../../src/adapters/repository/in-memory-sso-session-store.js';
import { sha256Hex } from '../../../src/domain/shared/hash.js';
import type { AuthSnapshot } from '../../../src/domain/login/authorization-code.js';
import { advanceableClock } from '../../helpers/advanceable-clock.js';

const TTL = 86400;
const auth: AuthSnapshot = { provider: 'google', email: 'a@b.c' };

function makeService() {
  const store = new InMemorySsoSessionStore();
  const clock = advanceableClock(new Date('2026-07-01T00:00:00Z'));
  const service = new SsoSessionService(store, clock, { ssoTtlSeconds: TTL });
  return { store, clock, service };
}

describe('SsoSessionService', () => {
  it('start: в сторе только хеш, expiresAt = now + ttl', async () => {
    const { service, clock } = makeService();
    const now = clock.now();
    const { session, rawToken } = await service.start('u1', auth);
    expect(session.tokenHash).toBe(sha256Hex(rawToken));
    expect(session.expiresAt.getTime()).toBe(now.getTime() + TTL * 1000);
  });

  it('resolve свежей сессии возвращает её; повторный resolve после advance продлевает expiresAt', async () => {
    const { service, clock } = makeService();
    const { session, rawToken } = await service.start('u1', auth);
    const first = await service.resolve(rawToken);
    expect(first!.id).toBe(session.id);
    clock.advance(TTL - 1);
    const second = await service.resolve(rawToken);
    expect(second!.expiresAt.getTime()).toBeGreaterThan(first!.expiresAt.getTime());
  });

  it('resolve неизвестного токена -> null', async () => {
    const { service } = makeService();
    expect(await service.resolve('unknown-token')).toBeNull();
  });

  it('resolve после revoke -> null', async () => {
    const { service } = makeService();
    const { session, rawToken } = await service.start('u1', auth);
    await service.revoke(session.id);
    expect(await service.resolve(rawToken)).toBeNull();
  });

  it('resolve после истечения ttl -> null', async () => {
    const { service, clock } = makeService();
    const { rawToken } = await service.start('u1', auth);
    clock.advance(TTL + 1);
    expect(await service.resolve(rawToken)).toBeNull();
  });
});
