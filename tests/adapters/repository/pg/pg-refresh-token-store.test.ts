import { newDb } from 'pg-mem';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { createMemDb, registerPgStubs } from '../../../helpers/pg-mem-db.js';
import { runMigrations } from '../../../../src/adapters/db/migrate.js';
import type { Db } from '../../../../src/adapters/db/pool.js';
import type { RefreshTokenRecord } from '../../../../src/domain/sessions/refresh-token.js';
import { PgRefreshTokenStore } from '../../../../src/adapters/repository/pg/pg-refresh-token-store.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../migrations',
);

async function makeSessionRow(db: Db): Promise<string> {
  const id = randomUUID();
  const now = new Date();
  await db.query(
    `insert into sessions
       (id, user_id, client_id, provider, profile, device_fingerprint, ip_hash,
        created_at, last_used_at, expires_at, revoked_at)
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [id, randomUUID(), 'app-1', 'google', '{}', 'fp', 'ip', now, now, now, null],
  );
  return id;
}

function makeRecord(
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

describe('PgRefreshTokenStore на pg-mem', () => {
  let db: Db;
  let store: PgRefreshTokenStore;
  let sessionId: string;

  beforeEach(async () => {
    db = createMemDb();
    await runMigrations(db, migrationsDir);
    store = new PgRefreshTokenStore(db);
    sessionId = await makeSessionRow(db);
  });

  afterEach(async () => {
    await db.close();
  });

  it('save -> findByHash/findById round-trip (null-поля корректны)', async () => {
    const record = makeRecord(sessionId);
    await store.save(record);

    expect(await store.findByHash(record.tokenHash)).toEqual(record);
    expect(await store.findById(record.id)).toEqual(record);
  });

  it('round-trip с previous_token_id/replaced_by_id/consumed_at заданными', async () => {
    const record = makeRecord(sessionId, {
      previousTokenId: randomUUID(),
      replacedById: randomUUID(),
      consumedAt: new Date('2026-01-02T00:00:00.000Z'),
    });
    await store.save(record);

    const found = await store.findById(record.id);
    expect(found?.previousTokenId).toBe(record.previousTokenId);
    expect(found?.replacedById).toBe(record.replacedById);
    expect(found?.consumedAt).toEqual(record.consumedAt);
  });

  it('неизвестный hash/id -> null', async () => {
    expect(await store.findByHash('nope')).toBeNull();
    expect(await store.findById(randomUUID())).toBeNull();
  });

  it('consume первый раз -> true, проставляет consumed_at + replaced_by_id', async () => {
    const record = makeRecord(sessionId);
    await store.save(record);

    const replacedById = randomUUID();
    const at = new Date('2026-01-03T00:00:00.000Z');
    expect(await store.consume(record.id, replacedById, at)).toBe(true);

    const found = await store.findById(record.id);
    expect(found?.consumedAt).toEqual(at);
    expect(found?.replacedById).toBe(replacedById);
  });

  it('повторный consume того же id -> false (CAS-идемпотентность)', async () => {
    const record = makeRecord(sessionId);
    await store.save(record);

    const first = await store.consume(record.id, randomUUID(), new Date());
    expect(first).toBe(true);

    const second = await store.consume(record.id, randomUUID(), new Date());
    expect(second).toBe(false);
  });
  it('rotate atomically publishes the pair; CAS loser cannot leave an orphan', async () => {
    const head = makeRecord(sessionId);
    await store.save(head);
    const child = makeRecord(sessionId, { previousTokenId: head.id, derivationVersion: 'hmac-sha256-v1' });
    const losingChild = makeRecord(sessionId, { previousTokenId: head.id });
    expect(await store.rotate(head.id, child, new Date())).toBe(true);
    expect(await store.rotate(head.id, losingChild, new Date())).toBe(false);
    expect((await store.findById(head.id))?.replacedById).toBe(child.id);
    expect(await store.findById(child.id)).toEqual(child);
    expect(await store.findById(losingChild.id)).toBeNull();
  });

  it('injected insert failure rolls back head consumption and permits retry', async () => {
    // pg-mem's BEGIN/ROLLBACK do not undo writes. This test uses its snapshot
    // rollback facility to implement the Db transaction contract faithfully.
    const mem = newDb({ noAstCoverageCheck: true });
    registerPgStubs(mem);
    const pool = new (mem.adapters.createPg().Pool)();
    const query: Db['query'] = async (sql, params) => {
      const result = await pool.query(sql, params);
      return { rows: result.rows, rowCount: result.rowCount ?? 0 };
    };
    let failInsert = false;
    let rolledBack = false;
    let inside = false;
    const transactional: Db = {
      query: async (sql, params) => {
        if (inside) throw new Error('rotation escaped its transaction');
        return query(sql, params);
      },
      withTransaction: async (fn) => {
        const backup = mem.backup();
        inside = true;
        const tx: Db = { query: async (sql, params) => {
          if (failInsert && /insert into refresh_tokens/.test(sql)) throw new Error('injected insert failure');
          return query(sql, params);
        }, withTransaction: (nested) => nested(tx), withConnection: (nested) => nested(tx), close: async () => {} };
        try { return await fn(tx); }
        catch (err) { backup.restore(); rolledBack = true; throw err; }
        finally { inside = false; }
      },
      withConnection: (fn) => fn(transactional),
      close: async () => { await pool.end(); },
    };
    try {
      // Schema changes cannot be snapshot-rolled back by pg-mem; migrations
      // use the existing helper while the failure test runs only DML.
      await runMigrations({ ...transactional, withTransaction: (fn) => fn({
        ...transactional, query,
      }) }, migrationsDir);
      const id = await makeSessionRow(transactional);
      const subject = new PgRefreshTokenStore(transactional);
      const head = makeRecord(id);
      const child = makeRecord(id, { previousTokenId: head.id, derivationVersion: 'hmac-sha256-v1' });
      await subject.save(head);
      failInsert = true;
      await expect(subject.rotate(head.id, child, new Date())).rejects.toThrow('injected insert failure');
      expect(rolledBack).toBe(true);
      expect(await subject.findById(head.id)).toEqual(head);
      expect(await subject.findById(child.id)).toBeNull();
      failInsert = false;
      expect(await subject.rotate(head.id, child, new Date())).toBe(true);
      expect(await subject.findById(child.id)).toEqual(child);
    } finally { await transactional.close(); }
  });

});
