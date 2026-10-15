import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMemDb } from '../../helpers/pg-mem-db.js';
import { runMigrations } from '../../../src/adapters/db/migrate.js';
import type { Db } from '../../../src/adapters/db/pool.js';
import type { StoredSigningKey } from '../../../src/domain/tokens/signing-key-store.js';
import { PgSigningKeyStore } from '../../../src/adapters/repository/pg/pg-signing-key-store.js';
import { describeRotation, runRotate, runRevoke } from '../../../src/adapters/db/rotate-key.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../migrations',
);

function makeKey(overrides: Partial<StoredSigningKey> = {}): StoredSigningKey {
  return {
    kid: `kid-${Math.random().toString(36).slice(2)}`,
    privatePem: 'storage-only-private-placeholder',
    publicPem: '-----BEGIN PUBLIC KEY-----\npub\n-----END PUBLIC KEY-----',
    alg: 'RS256',
    status: 'active',
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    retiredAt: null,
    revokedAt: null,
    ...overrides,
  };
}

describe('runRotate на pg-mem', () => {
  let db: Db;

  beforeEach(async () => {
    db = createMemDb();
    await runMigrations(db, migrationsDir);
  });

  afterEach(async () => {
    await db.close();
  });

  it('снимает прежний active в retired и делает новый ключ active', async () => {
    const store = new PgSigningKeyStore(db);
    await store.insertActive(makeKey({ kid: 'a' }));

    const now = new Date('2026-03-01T00:00:00.000Z');
    const result = await runRotate(db, now);

    const all = await store.listAll();
    expect(all).toHaveLength(2);

    const retired = all.find((k) => k.kid === 'a');
    expect(retired?.status).toBe('retired');
    expect(retired?.retiredAt).not.toBeNull();

    const fresh = all.find((k) => k.kid === result.newKid);
    expect(fresh?.status).toBe('active');

    expect((await store.getActive())?.kid).toBe(result.newKid);
    expect(result.retiredKids).toEqual(['a']);
    expect(describeRotation(result)).toBe(`Новый активный ключ: ${result.newKid}; отправлены в retired: a`);
  });

  it('на пустой БД создаёт первый active, в retired никого', async () => {
    const store = new PgSigningKeyStore(db);

    const result = await runRotate(db, new Date('2026-03-01T00:00:00.000Z'));

    expect(result.retiredKids).toEqual([]);
    expect(describeRotation(result)).toBe(`Новый активный ключ: ${result.newKid}; отправлены в retired: нет`);
    const active = await store.getActive();
    expect(active?.kid).toBe(result.newKid);
    expect(await store.listAll()).toHaveLength(1);
  });
});

describe('runRevoke на pg-mem', () => {
  let db: Db;

  beforeEach(async () => {
    db = createMemDb();
    await runMigrations(db, migrationsDir);
  });

  afterEach(async () => {
    await db.close();
  });

  it('отзывает retired-ключ: проставляет revokedAt', async () => {
    const store = new PgSigningKeyStore(db);
    await store.insertActive(makeKey({ kid: 'old' }));
    // Ротация переводит 'old' в retired.
    await runRotate(db, new Date('2026-03-01T00:00:00.000Z'));

    const at = new Date('2026-03-02T00:00:00.000Z');
    await runRevoke(db, 'old', at);

    const revoked = (await store.listAll()).find((k) => k.kid === 'old');
    expect(revoked?.revokedAt).toEqual(at);
  });

  it('отказывается отзывать active-ключ (сначала нужна ротация)', async () => {
    const store = new PgSigningKeyStore(db);
    await store.insertActive(makeKey({ kid: 'live' }));

    await expect(
      runRevoke(db, 'live', new Date('2026-03-02T00:00:00.000Z')),
    ).rejects.toThrow(/активен/);

    const still = (await store.listAll()).find((k) => k.kid === 'live');
    expect(still?.revokedAt).toBeNull();
  });

  it('на несуществующем kid бросает ошибку', async () => {
    await expect(
      runRevoke(db, 'ghost', new Date('2026-03-02T00:00:00.000Z')),
    ).rejects.toThrow(/не найден/);
  });
});
