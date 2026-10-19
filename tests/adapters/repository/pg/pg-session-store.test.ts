import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { createMemDb } from '../../../helpers/pg-mem-db.js';
import { runMigrations } from '../../../../src/adapters/db/migrate.js';
import type { Db } from '../../../../src/adapters/db/pool.js';
import type { Session } from '../../../../src/domain/sessions/session.js';
import { PgSessionStore } from '../../../../src/adapters/repository/pg/pg-session-store.js';
import { PgRefreshTokenStore } from '../../../../src/adapters/repository/pg/pg-refresh-token-store.js';
import type { RefreshTokenRecord } from '../../../../src/domain/sessions/refresh-token.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../migrations',
);

function makeSession(overrides: Partial<Session> = {}): Session {
  const now = new Date('2026-01-01T00:00:00.000Z');
  return {
    id: randomUUID(),
    userId: randomUUID(),
    clientId: 'app-1',
    provider: 'google',
    profile: { email: 'a@b.com', emailVerified: true, name: 'Alice' },
    scope: 'openid profile email',
    deviceFingerprint: 'fp-1',
    ipHash: 'ip-1',
    createdAt: now,
    lastUsedAt: now,
    expiresAt: new Date('2026-01-08T00:00:00.000Z'),
    revokedAt: null,
    ...overrides,
  };
}

describe('PgSessionStore на pg-mem', () => {
  let db: Db;
  let store: PgSessionStore;

  beforeEach(async () => {
    db = createMemDb();
    await runMigrations(db, migrationsDir);
    store = new PgSessionStore(db);
  });

  afterEach(async () => {
    await db.close();
  });

  it('save -> findById round-trip, profile совпадает', async () => {
    const session = makeSession();
    await store.save(session);

    const found = await store.findById(session.id);
    expect(found).toEqual(session);
    expect(found?.profile).toEqual(session.profile);
  });

  it('T12: ssoChainId переживает round-trip; revokeForSsoChain гасит только цепочку', async () => {
    const chain = randomUUID();
    const user = randomUUID();
    const inChain = makeSession({ ssoChainId: chain });
    const otherChain = makeSession({ ssoChainId: randomUUID() });
    const sameUser = makeSession({ userId: user });
    const userInChain = makeSession({ userId: user, ssoChainId: chain });
    const noChain = makeSession();
    for (const s of [inChain, otherChain, sameUser, userInChain, noChain]) await store.save(s);
    expect(await store.findById(inChain.id)).toEqual(inChain);
    expect((await store.findById(noChain.id))).not.toHaveProperty('ssoChainId');

    const at = new Date('2026-01-02T00:00:00.000Z');
    await store.revokeForSsoChain(chain, at);
    expect((await store.findById(inChain.id))?.revokedAt).toEqual(at);
    expect((await store.findById(userInChain.id))?.revokedAt).toEqual(at);
    // Тот же пользователь в другом браузере (без этой цепочки) остаётся.
    expect((await store.findById(sameUser.id))?.revokedAt).toBeNull();
    expect((await store.findById(otherChain.id))?.revokedAt).toBeNull();
    expect((await store.findById(noChain.id))?.revokedAt).toBeNull();
  });

  it('A5: revokeOthersInSsoChain гасит в цепочке сессии других пользователей, свои и чужие цепочки не трогает', async () => {
    const chain = randomUUID();
    const keep = randomUUID();
    const kept = makeSession({ userId: keep, ssoChainId: chain });
    const other = makeSession({ ssoChainId: chain });
    const otherChain = makeSession({ ssoChainId: randomUUID() });
    for (const s of [kept, other, otherChain]) await store.save(s);
    const at = new Date('2026-01-02T00:00:00.000Z');
    await store.revokeOthersInSsoChain(chain, keep, at);
    expect((await store.findById(other.id))?.revokedAt).toEqual(at);
    expect((await store.findById(kept.id))?.revokedAt).toBeNull();
    expect((await store.findById(otherChain.id))?.revokedAt).toBeNull();
  });

  it('findById неизвестного -> null', async () => {
    expect(await store.findById(randomUUID())).toBeNull();
  });

  it('touch меняет last_used_at/expires_at/device', async () => {
    const session = makeSession();
    await store.save(session);

    const at = new Date('2026-01-02T00:00:00.000Z');
    const expiresAt = new Date('2026-01-09T00:00:00.000Z');
    await store.touch(session.id, at, expiresAt, {
      fingerprint: 'fp-2',
      ipHash: 'ip-2',
    });

    const found = await store.findById(session.id);
    expect(found?.lastUsedAt).toEqual(at);
    expect(found?.expiresAt).toEqual(expiresAt);
    expect(found?.deviceFingerprint).toBe('fp-2');
    expect(found?.ipHash).toBe('ip-2');
  });

  it('revoke ставит revoked_at и убирает из findActiveByUser', async () => {
    const session = makeSession();
    await store.save(session);

    const now = new Date('2026-01-03T00:00:00.000Z');
    expect(await store.findActiveByUser(session.userId, now)).toHaveLength(1);

    const at = new Date('2026-01-03T12:00:00.000Z');
    await store.revoke(session.id, at);

    const found = await store.findById(session.id);
    expect(found?.revokedAt).toEqual(at);
    expect(await store.findActiveByUser(session.userId, now)).toEqual([]);
  });

  it('findActiveByUser не возвращает истёкшие и отозванные', async () => {
    const userId = randomUUID();
    const now = new Date('2026-01-05T00:00:00.000Z');

    const active = makeSession({
      userId,
      expiresAt: new Date('2026-01-20T00:00:00.000Z'),
    });
    const expired = makeSession({
      userId,
      expiresAt: new Date('2026-01-01T00:00:00.000Z'),
    });
    const revoked = makeSession({
      userId,
      expiresAt: new Date('2026-01-20T00:00:00.000Z'),
      revokedAt: new Date('2026-01-04T00:00:00.000Z'),
    });
    await store.save(active);
    await store.save(expired);
    await store.save(revoked);

    const found = await store.findActiveByUser(userId, now);
    expect(found.map((s) => s.id)).toEqual([active.id]);
  });

  it('deleteExpired не трогает живую сессию', async () => {
    const session = makeSession({ expiresAt: new Date('2026-01-31T00:00:00.000Z') });
    await store.save(session);

    const deleted = await store.deleteExpired(new Date('2026-01-01T00:00:00.000Z'));
    expect(deleted).toBe(0);
    expect(await store.findById(session.id)).not.toBeNull();
  });

  it('deleteExpired удаляет истёкшую сессию и возвращает счётчик', async () => {
    const session = makeSession({ expiresAt: new Date('2026-01-01T00:00:00.000Z') });
    await store.save(session);

    const deleted = await store.deleteExpired(new Date('2026-01-02T00:00:00.000Z'));
    expect(deleted).toBe(1);
    expect(await store.findById(session.id)).toBeNull();
  });

  it('deleteExpired удаляет давно отозванную сессию, но не недавно отозванную', async () => {
    const oldRevoked = makeSession({
      expiresAt: new Date('2026-03-01T00:00:00.000Z'),
      revokedAt: new Date('2026-01-01T00:00:00.000Z'),
    });
    const recentRevoked = makeSession({
      expiresAt: new Date('2026-03-01T00:00:00.000Z'),
      revokedAt: new Date('2026-01-29T12:00:00.000Z'),
    });
    await store.save(oldRevoked);
    await store.save(recentRevoked);

    const before = new Date('2026-01-29T00:00:00.000Z');
    const deleted = await store.deleteExpired(before);
    expect(deleted).toBe(1);
    expect(await store.findById(oldRevoked.id)).toBeNull();
    expect(await store.findById(recentRevoked.id)).not.toBeNull();
  });

  it('deleteExpired удаляет refresh-токены удалённой сессии, но не трогает токены живой (в одной транзакции)', async () => {
    const refreshStore = new PgRefreshTokenStore(db);
    const live = makeSession({ expiresAt: new Date('2026-01-31T00:00:00.000Z') });
    const expired = makeSession({ expiresAt: new Date('2026-01-01T00:00:00.000Z') });
    await store.save(live);
    await store.save(expired);

    function makeRefreshToken(
      sessionId: string,
      overrides: Partial<RefreshTokenRecord> = {},
    ): RefreshTokenRecord {
      return {
        id: randomUUID(),
        sessionId,
        tokenHash: `hash-${randomUUID()}`,
        previousTokenId: null,
        replacedById: null,
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        consumedAt: null,
        ...overrides,
      };
    }

    const liveToken = makeRefreshToken(live.id);
    const expiredToken = makeRefreshToken(expired.id);
    await refreshStore.save(liveToken);
    await refreshStore.save(expiredToken);

    await store.deleteExpired(new Date('2026-01-02T00:00:00.000Z'));

    expect(await refreshStore.findByHash(expiredToken.tokenHash)).toBeNull();
    expect(await refreshStore.findByHash(liveToken.tokenHash)).not.toBeNull();
  });
  it('revokeForClient retains allowed providers and other clients, without resetting existing revocations', async () => {
    const email = makeSession({ provider: 'email' });
    const google = makeSession({ provider: 'google' });
    const other = makeSession({ clientId: 'other', provider: 'email' });
    const already = makeSession({ provider: 'email', revokedAt: new Date('2026-01-02T00:00:00Z') });
    for (const session of [email, google, other, already]) await store.save(session);
    const at = new Date('2026-01-03T00:00:00Z');
    await store.revokeForClient('app-1', at, ['google']);
    expect((await store.findById(email.id))?.revokedAt).toEqual(at);
    expect((await store.findById(google.id))?.revokedAt).toBeNull();
    expect((await store.findById(other.id))?.revokedAt).toBeNull();
    expect((await store.findById(already.id))?.revokedAt).toEqual(already.revokedAt);
    await store.revokeForClient('app-1', at);
    expect((await store.findById(google.id))?.revokedAt).toEqual(at);
    expect((await store.findById(other.id))?.revokedAt).toBeNull();
  });

  it('revokeForUser гасит сессии пользователя во всех клиентах, не трогая чужие и прежние отзывы', async () => {
    const out = '00000000-0000-4000-8000-0000000000aa';
    const stay = '00000000-0000-4000-8000-0000000000bb';
    const mine = makeSession({ userId: out });
    const mineOther = makeSession({ userId: out, clientId: 'other' });
    const already = makeSession({ userId: out, revokedAt: new Date('2026-01-02T00:00:00Z') });
    const stranger = makeSession({ userId: stay });
    for (const session of [mine, mineOther, already, stranger]) await store.save(session);
    const at = new Date('2026-01-03T00:00:00Z');
    await store.revokeForUser(out, at);
    expect((await store.findById(mine.id))?.revokedAt).toEqual(at);
    expect((await store.findById(mineOther.id))?.revokedAt).toEqual(at);
    expect((await store.findById(already.id))?.revokedAt).toEqual(already.revokedAt);
    expect((await store.findById(stranger.id))?.revokedAt).toBeNull();
  });

});
