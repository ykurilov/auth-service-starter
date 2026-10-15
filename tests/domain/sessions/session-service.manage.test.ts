import { describe, it, expect } from 'vitest';
import { SessionService } from '../../../src/domain/sessions/session-service.js';
import { InMemorySessionStore } from '../../../src/adapters/repository/in-memory-session-store.js';
import { InMemoryRefreshTokenStore } from '../../../src/adapters/repository/in-memory-refresh-token-store.js';
import { TokenService } from '../../../src/domain/tokens/token-service.js';
import { loadSigningKey } from '../../../src/domain/tokens/signing-key.js';
import { InvalidRefreshTokenError } from '../../../src/domain/sessions/errors.js';
import { advanceableClock } from '../../helpers/advanceable-clock.js';

async function setup() {
  const key = await loadSigningKey({ autogenerate: true });
  const clock = advanceableClock(new Date('2026-07-01T00:00:00Z'));
  const tokens = new TokenService(key, [key], clock, {
    issuer: 'https://auth',
    accessTtlSeconds: 900,
    idTtlSeconds: 900,
  });
  const refreshTokens = new InMemoryRefreshTokenStore();
  const service = new SessionService(
    new InMemorySessionStore(refreshTokens),
    refreshTokens,
    tokens,
    clock,
    { refreshTtlSeconds: 2592000 },
  );
  return { service };
}

const base = {
  userId: 'u1',
  clientId: 'app',
  provider: 'email',
  profile: { email: 'a@b.co', emailVerified: true },
  scope: 'openid profile email',
  device: { userAgent: 'UA', ip: '1.1.1.1' },
};

describe('SessionService управление', () => {
  it('revoke гасит сессию: её refresh больше не работает', async () => {
    const { service } = await setup();
    const s = await service.start(base);
    await service.revoke(s.sessionId);
    await expect(
      service.refresh(s.refreshToken, base.device),
    ).rejects.toBeInstanceOf(InvalidRefreshTokenError);
  });

  it('listForUser отдаёт живые сессии пользователя', async () => {
    const { service } = await setup();
    const s1 = await service.start(base);
    await service.start({ ...base, device: { userAgent: 'UA2', ip: '2.2.2.2' } });
    const list = await service.listForUser('u1');
    expect(list.length).toBe(2);
    await service.revoke(s1.sessionId);
    expect((await service.listForUser('u1')).length).toBe(1);
  });

  it('revokeAllForUser гасит сессии пользователя во всех приложениях', async () => {
    const { service } = await setup();
    await service.start({
      ...base,
      clientId: 'app1',
      device: { userAgent: 'UA1', ip: '1.1.1.1' },
    });
    await service.start({
      ...base,
      clientId: 'app2',
      device: { userAgent: 'UA2', ip: '2.2.2.2' },
    });
    await service.start({ ...base, userId: 'u2' });
    await service.revokeAllForUser('u1');
    expect(await service.listForUser('u1')).toEqual([]);
    expect((await service.listForUser('u2')).length).toBe(1);
  });
});
