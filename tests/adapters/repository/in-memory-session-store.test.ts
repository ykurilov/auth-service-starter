import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { InMemorySessionStore } from '../../../src/adapters/repository/in-memory-session-store.js';
import { InMemoryRefreshTokenStore } from '../../../src/adapters/repository/in-memory-refresh-token-store.js';
import type { Session } from '../../../src/domain/sessions/session.js';
import type { RefreshTokenRecord } from '../../../src/domain/sessions/refresh-token.js';

function make(overrides: Partial<Session> = {}): Session {
  const t = new Date('2026-07-01T00:00:00Z');
  return {
    id: 's1', userId: 'u1', clientId: 'app', provider: 'email',
    profile: { email: 'a@b.co', emailVerified: true, name: 'Аня' },
    scope: 'openid profile email',
    deviceFingerprint: 'fp', ipHash: 'iph',
    createdAt: t, lastUsedAt: t, expiresAt: new Date('2026-07-31T00:00:00Z'),
    revokedAt: null, ...overrides,
  };
}

describe('InMemorySessionStore', () => {
  it('save + findById возвращает копию', async () => {
    const store = new InMemorySessionStore(new InMemoryRefreshTokenStore());
    const s = make();
    await store.save(s);
    const got = await store.findById('s1');
    expect(got).not.toBeNull();
    expect(got).not.toBe(s);
    expect(got!.userId).toBe('u1');
  });

  it('findById -> null для неизвестного', async () => {
    const store = new InMemorySessionStore(new InMemoryRefreshTokenStore());
    expect(await store.findById('nope')).toBeNull();
  });

  it('touch двигает lastUsedAt/expiresAt и аудит устройства', async () => {
    const store = new InMemorySessionStore(new InMemoryRefreshTokenStore());
    await store.save(make());
    const at = new Date('2026-07-05T00:00:00Z');
    const exp = new Date('2026-08-04T00:00:00Z');
    await store.touch('s1', at, exp, { fingerprint: 'fp2', ipHash: 'iph2' });
    const got = await store.findById('s1');
    expect(got!.lastUsedAt).toEqual(at);
    expect(got!.expiresAt).toEqual(exp);
    expect(got!.deviceFingerprint).toBe('fp2');
    expect(got!.ipHash).toBe('iph2');
  });

  it('revoke ставит revokedAt', async () => {
    const store = new InMemorySessionStore(new InMemoryRefreshTokenStore());
    await store.save(make());
    const at = new Date('2026-07-06T00:00:00Z');
    await store.revoke('s1', at);
    expect((await store.findById('s1'))!.revokedAt).toEqual(at);
  });

  it('findActiveByUser отдаёт только живые', async () => {
    const store = new InMemorySessionStore(new InMemoryRefreshTokenStore());
    const now = new Date('2026-07-10T00:00:00Z');
    await store.save(make({ id: 's1' }));
    await store.save(make({ id: 's2', revokedAt: new Date('2026-07-02T00:00:00Z') }));
    await store.save(make({ id: 's3', expiresAt: new Date('2026-07-05T00:00:00Z') }));
    const active = await store.findActiveByUser('u1', now);
    expect(active.map((s) => s.id)).toEqual(['s1']);
  });

  function makeRefreshToken(sessionId: string, overrides: Partial<RefreshTokenRecord> = {}): RefreshTokenRecord {
    return {
      id: randomUUID(),
      sessionId,
      tokenHash: `hash-${randomUUID()}`,
      previousTokenId: null,
      replacedById: null,
      createdAt: new Date('2026-07-01T00:00:00Z'),
      consumedAt: null,
      ...overrides,
    };
  }

  it('deleteExpired не трогает живую сессию', async () => {
    const refresh = new InMemoryRefreshTokenStore();
    const store = new InMemorySessionStore(refresh);
    await store.save(make({ id: 'live', expiresAt: new Date('2026-07-31T00:00:00Z') }));

    const deleted = await store.deleteExpired(new Date('2026-07-01T00:00:00Z'));
    expect(deleted).toBe(0);
    expect(await store.findById('live')).not.toBeNull();
  });

  it('deleteExpired удаляет истёкшую сессию и возвращает счётчик', async () => {
    const refresh = new InMemoryRefreshTokenStore();
    const store = new InMemorySessionStore(refresh);
    await store.save(make({ id: 'expired', expiresAt: new Date('2026-07-01T00:00:00Z') }));

    const deleted = await store.deleteExpired(new Date('2026-07-02T00:00:00Z'));
    expect(deleted).toBe(1);
    expect(await store.findById('expired')).toBeNull();
  });

  it('deleteExpired удаляет давно отозванную сессию, но не недавно отозванную', async () => {
    const refresh = new InMemoryRefreshTokenStore();
    const store = new InMemorySessionStore(refresh);
    await store.save(
      make({
        id: 'old-revoked',
        expiresAt: new Date('2026-08-01T00:00:00Z'),
        revokedAt: new Date('2026-06-01T00:00:00Z'),
      }),
    );
    await store.save(
      make({
        id: 'recent-revoked',
        expiresAt: new Date('2026-08-01T00:00:00Z'),
        revokedAt: new Date('2026-06-30T12:00:00Z'),
      }),
    );

    const before = new Date('2026-06-30T00:00:00Z');
    const deleted = await store.deleteExpired(before);
    expect(deleted).toBe(1);
    expect(await store.findById('old-revoked')).toBeNull();
    expect(await store.findById('recent-revoked')).not.toBeNull();
  });

  it('deleteExpired удаляет refresh-токены удалённой сессии, но не трогает токены живой', async () => {
    const refresh = new InMemoryRefreshTokenStore();
    const store = new InMemorySessionStore(refresh);
    await store.save(make({ id: 'live', expiresAt: new Date('2026-07-31T00:00:00Z') }));
    await store.save(make({ id: 'expired', expiresAt: new Date('2026-07-01T00:00:00Z') }));
    const liveToken = makeRefreshToken('live', { tokenHash: 'live-hash' });
    const expiredToken = makeRefreshToken('expired', { tokenHash: 'expired-hash' });
    await refresh.save(liveToken);
    await refresh.save(expiredToken);

    await store.deleteExpired(new Date('2026-07-02T00:00:00Z'));

    expect(await refresh.findByHash('expired-hash')).toBeNull();
    expect(await refresh.findByHash('live-hash')).not.toBeNull();
  });
  it('client policy revocation retains allowed providers and other clients', async () => {
    const store = new InMemorySessionStore(new InMemoryRefreshTokenStore());
    await store.save(make());
    await store.save(make({ id: 'google', provider: 'google' }));
    await store.save(make({ id: 'other', clientId: 'other' }));
    const at = new Date('2026-07-06T00:00:00Z');
    await store.revokeForClient('app', at, ['google']);
    expect((await store.findById('s1'))?.revokedAt).toEqual(at);
    expect((await store.findById('google'))?.revokedAt).toBeNull();
    expect((await store.findById('other'))?.revokedAt).toBeNull();
    await store.revokeForClient('app', at);
    expect((await store.findById('google'))?.revokedAt).toEqual(at);
    expect((await store.findById('other'))?.revokedAt).toBeNull();
  });
  it('revokeForUser гасит сессии пользователя во всех клиентах, не трогая чужие', async () => {
    const store = new InMemorySessionStore(new InMemoryRefreshTokenStore());
    await store.save(make());
    await store.save(make({ id: 'other-client', clientId: 'other' }));
    await store.save(make({ id: 'stranger', userId: 'someone-else' }));
    const at = new Date('2026-07-06T00:00:00Z');
    await store.revokeForUser(make().userId, at);
    expect((await store.findById('s1'))?.revokedAt).toEqual(at);
    expect((await store.findById('other-client'))?.revokedAt).toEqual(at);
    expect((await store.findById('stranger'))?.revokedAt).toBeNull();
  });

});
