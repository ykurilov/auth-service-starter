import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { createMemDb } from '../../../helpers/pg-mem-db.js';
import { runMigrations } from '../../../../src/adapters/db/migrate.js';
import type { Db } from '../../../../src/adapters/db/pool.js';
import type { SsoSession } from '../../../../src/domain/sso/sso-session.js';
import { PgSsoSessionStore } from '../../../../src/adapters/repository/pg/pg-sso-session-store.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../migrations',
);

function makeSsoSession(overrides: Partial<SsoSession> = {}): SsoSession {
  const now = new Date('2026-01-01T00:00:00.000Z');
  return {
    id: randomUUID(),
    userId: randomUUID(),
    auth: {
      provider: 'google',
      email: 'a@b.com',
      emailVerified: true,
      name: 'Alice',
    },
    tokenHash: `hash-${randomUUID()}`,
    chainId: randomUUID(),
    createdAt: now,
    lastUsedAt: now,
    expiresAt: new Date('2026-01-08T00:00:00.000Z'),
    revokedAt: null,
    ...overrides,
  };
}

describe('PgSsoSessionStore на pg-mem', () => {
  let db: Db;
  let store: PgSsoSessionStore;

  beforeEach(async () => {
    db = createMemDb();
    await runMigrations(db, migrationsDir);
    store = new PgSsoSessionStore(db);
  });

  afterEach(async () => {
    await db.close();
  });

  it('save -> findByHash round-trip, auth совпадает', async () => {
    const session = makeSsoSession();
    await store.save(session);

    const found = await store.findByHash(session.tokenHash);
    expect(found).toEqual(session);
    expect(found?.auth).toEqual(session.auth);
  });

  it('T12: findByLogin по auth.loginId; revokeChain гасит только живые сессии своей цепочки', async () => {
    const chain = randomUUID();
    const first = makeSsoSession({ chainId: chain, auth: { provider: 'email', loginId: 'login-1' } });
    const earlier = new Date('2025-12-31T00:00:00.000Z');
    const revokedBefore = makeSsoSession({ chainId: chain, revokedAt: earlier });
    const other = makeSsoSession({ auth: { provider: 'email', loginId: 'login-2' } });
    for (const s of [first, revokedBefore, other]) await store.save(s);
    expect(await store.findByLogin('login-1')).toEqual(first);
    expect(await store.findByLogin('nope')).toBeNull();

    const at = new Date('2026-01-02T00:00:00.000Z');
    await store.revokeChain(chain, at);
    expect((await store.findByHash(first.tokenHash))?.revokedAt).toEqual(at);
    expect((await store.findByHash(revokedBefore.tokenHash))?.revokedAt).toEqual(earlier);
    expect((await store.findByHash(other.tokenHash))?.revokedAt).toBeNull();
  });

  it('findByHash неизвестного -> null', async () => {
    expect(await store.findByHash('nope')).toBeNull();
  });

  it('touch продлевает last_used_at/expires_at', async () => {
    const session = makeSsoSession();
    await store.save(session);

    const lastUsedAt = new Date('2026-01-02T00:00:00.000Z');
    const expiresAt = new Date('2026-01-09T00:00:00.000Z');
    await store.touch(session.id, lastUsedAt, expiresAt);

    const found = await store.findByHash(session.tokenHash);
    expect(found?.lastUsedAt).toEqual(lastUsedAt);
    expect(found?.expiresAt).toEqual(expiresAt);
  });

  it('revoke ставит revoked_at', async () => {
    const session = makeSsoSession();
    await store.save(session);

    const at = new Date('2026-01-03T00:00:00.000Z');
    await store.revoke(session.id, at);

    const found = await store.findByHash(session.tokenHash);
    expect(found?.revokedAt).toEqual(at);
  });

  it('deleteExpired не трогает живую сессию', async () => {
    const session = makeSsoSession({ expiresAt: new Date('2026-01-08T00:00:00.000Z') });
    await store.save(session);

    const deleted = await store.deleteExpired(new Date('2026-01-01T00:00:00.000Z'));
    expect(deleted).toBe(0);
    expect(await store.findByHash(session.tokenHash)).not.toBeNull();
  });

  it('deleteExpired удаляет истёкшую сессию и возвращает счётчик', async () => {
    const session = makeSsoSession({ expiresAt: new Date('2026-01-01T00:00:00.000Z') });
    await store.save(session);

    const deleted = await store.deleteExpired(new Date('2026-01-02T00:00:00.000Z'));
    expect(deleted).toBe(1);
    expect(await store.findByHash(session.tokenHash)).toBeNull();
  });

  it('deleteExpired удаляет давно отозванную сессию, но не недавно отозванную', async () => {
    const oldRevoked = makeSsoSession({
      expiresAt: new Date('2026-02-01T00:00:00.000Z'),
      revokedAt: new Date('2025-12-01T00:00:00.000Z'),
    });
    const recentRevoked = makeSsoSession({
      expiresAt: new Date('2026-02-01T00:00:00.000Z'),
      revokedAt: new Date('2025-12-30T12:00:00.000Z'),
    });
    await store.save(oldRevoked);
    await store.save(recentRevoked);

    const before = new Date('2025-12-30T00:00:00.000Z');
    const deleted = await store.deleteExpired(before);
    expect(deleted).toBe(1);
    expect(await store.findByHash(oldRevoked.tokenHash)).toBeNull();
    expect(await store.findByHash(recentRevoked.tokenHash)).not.toBeNull();
  });
});
