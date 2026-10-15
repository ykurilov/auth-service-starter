import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMemDb } from '../../../helpers/pg-mem-db.js';
import { runMigrations } from '../../../../src/adapters/db/migrate.js';
import type { Db } from '../../../../src/adapters/db/pool.js';
import type { StoredSigningKey } from '../../../../src/domain/tokens/signing-key-store.js';
import { PgSigningKeyStore } from '../../../../src/adapters/repository/pg/pg-signing-key-store.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../migrations',
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

describe('PgSigningKeyStore на pg-mem', () => {
  let db: Db;
  let store: PgSigningKeyStore;

  beforeEach(async () => {
    db = createMemDb();
    await runMigrations(db, migrationsDir);
    store = new PgSigningKeyStore(db);
  });

  afterEach(async () => {
    await db.close();
  });

  it('insertActive -> getActive round-trip (null retiredAt корректен)', async () => {
    const key = makeKey();
    await store.insertActive(key);

    expect(await store.getActive()).toEqual(key);
  });

  it('getActive без ключей -> null', async () => {
    expect(await store.getActive()).toBeNull();
  });

  it('listAll возвращает все ключи', async () => {
    const active = makeKey({ kid: 'a' });
    await store.insertActive(active);
    await store.rotate(makeKey({ kid: 'b' }), new Date('2026-02-01T00:00:00.000Z'));

    const all = await store.listAll();
    expect(all.map((k) => k.kid).sort()).toEqual(['a', 'b']);
  });

  it('rotate снимает прежний active (retired + retiredAt) и делает новый active', async () => {
    await store.insertActive(makeKey({ kid: 'old' }));

    const at = new Date('2026-02-01T00:00:00.000Z');
    await store.rotate(makeKey({ kid: 'new' }), at);

    expect((await store.getActive())?.kid).toBe('new');

    const all = await store.listAll();
    const retired = all.find((k) => k.kid === 'old');
    expect(retired?.status).toBe('retired');
    expect(retired?.retiredAt).toEqual(at);

    expect(all.filter((k) => k.status === 'active')).toHaveLength(1);
  });

  it('второй insertActive нарушает partial-unique (один active)', async () => {
    await store.insertActive(makeKey({ kid: 'a' }));
    await expect(store.insertActive(makeKey({ kid: 'b' }))).rejects.toThrow();
  });

  it('ensureActive на пустой БД создаёт active и возвращает его', async () => {
    const key = makeKey({ kid: 'seed' });
    const result = await store.ensureActive(key);

    expect(result.kid).toBe('seed');
    expect(await store.getActive()).toEqual(key);
  });

  it('ensureActive идемпотентен: повторный вызов возвращает существующий active', async () => {
    const first = await store.ensureActive(makeKey({ kid: 'first' }));
    const second = await store.ensureActive(makeKey({ kid: 'second' }));

    expect(first.kid).toBe('first');
    expect(second.kid).toBe('first');
    expect((await store.listAll()).filter((k) => k.status === 'active')).toHaveLength(1);
  });

  it('две параллельные попытки seed -> ровно один active, оба вызова дают один kid, никто не падает', async () => {
    const [a, b] = await Promise.all([
      store.ensureActive(makeKey({ kid: 'a' })),
      store.ensureActive(makeKey({ kid: 'b' })),
    ]);

    expect(a.kid).toBe(b.kid);

    const actives = (await store.listAll()).filter((k) => k.status === 'active');
    expect(actives).toHaveLength(1);
    expect(actives[0]!.kid).toBe(a.kid);
  });
});
