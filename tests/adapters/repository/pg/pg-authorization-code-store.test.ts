import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { createMemDb } from '../../../helpers/pg-mem-db.js';
import { runMigrations } from '../../../../src/adapters/db/migrate.js';
import type { Db } from '../../../../src/adapters/db/pool.js';
import type { AuthorizationCodeRecord } from '../../../../src/domain/login/authorization-code.js';
import { PgAuthorizationCodeStore } from '../../../../src/adapters/repository/pg/pg-authorization-code-store.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../migrations',
);

function makeRecord(
  overrides: Partial<AuthorizationCodeRecord> = {},
): AuthorizationCodeRecord {
  return {
    id: randomUUID(),
    codeHash: `hash-${randomUUID()}`,
    clientId: 'app-1',
    userId: randomUUID(),
    redirectUri: 'https://app.example/callback',
    codeChallenge: 'challenge-abc',
    scope: 'openid profile',
    nonce: 'nonce-123',
    auth: {
      provider: 'google',
      email: 'user@example.com',
      emailVerified: true,
      name: 'User Example',
    },
    expiresAt: new Date('2026-01-01T01:00:00.000Z'),
    consumedAt: null,
    ...overrides,
  };
}

describe('PgAuthorizationCodeStore на pg-mem', () => {
  let db: Db;
  let store: PgAuthorizationCodeStore;

  beforeEach(async () => {
    db = createMemDb();
    await runMigrations(db, migrationsDir);
    store = new PgAuthorizationCodeStore(db);
  });

  afterEach(async () => {
    await db.close();
  });

  it('save -> findActiveByHash round-trip С nonce (все поля, включая auth-снимок)', async () => {
    const record = makeRecord();
    await store.save(record);

    const found = await store.findActiveByHash(
      record.codeHash,
      new Date('2026-01-01T00:00:00.000Z'),
    );
    expect(found).toEqual(record);
  });

  it('save -> findActiveByHash round-trip БЕЗ nonce (поле отсутствует)', async () => {
    const record = makeRecord();
    delete (record as { nonce?: string }).nonce;
    await store.save(record);

    const found = await store.findActiveByHash(
      record.codeHash,
      new Date('2026-01-01T00:00:00.000Z'),
    );
    expect(found).toEqual(record);
    expect(found && 'nonce' in found).toBe(false);
  });

  it('findActiveByHash не находит истёкший код', async () => {
    const record = makeRecord({ expiresAt: new Date('2026-01-01T00:00:00.000Z') });
    await store.save(record);

    const found = await store.findActiveByHash(
      record.codeHash,
      new Date('2026-01-01T02:00:00.000Z'),
    );
    expect(found).toBeNull();
  });

  it('findActiveByHash не находит погашенный код', async () => {
    const record = makeRecord();
    await store.save(record);
    await store.consume(record.id, new Date('2026-01-01T00:30:00.000Z'));

    const found = await store.findActiveByHash(
      record.codeHash,
      new Date('2026-01-01T00:00:00.000Z'),
    );
    expect(found).toBeNull();
  });

  it('неизвестный hash -> null', async () => {
    expect(
      await store.findActiveByHash('nope', new Date('2026-01-01T00:00:00.000Z')),
    ).toBeNull();
  });

  it('consume первый раз -> true, после него findActiveByHash -> null', async () => {
    const record = makeRecord();
    await store.save(record);

    const at = new Date('2026-01-01T00:30:00.000Z');
    expect(await store.consume(record.id, at)).toBe(true);

    const found = await store.findActiveByHash(
      record.codeHash,
      new Date('2026-01-01T00:00:00.000Z'),
    );
    expect(found).toBeNull();
  });

  it('повторный consume того же id -> false (CAS)', async () => {
    const record = makeRecord();
    await store.save(record);

    expect(await store.consume(record.id, new Date('2026-01-01T00:30:00.000Z'))).toBe(true);
    expect(await store.consume(record.id, new Date('2026-01-01T00:40:00.000Z'))).toBe(false);
  });

  it('deleteExpired не трогает живой код', async () => {
    const record = makeRecord({ expiresAt: new Date('2026-01-01T01:00:00.000Z') });
    await store.save(record);

    const deleted = await store.deleteExpired(new Date('2026-01-01T00:00:00.000Z'));
    expect(deleted).toBe(0);
    expect(
      await store.findActiveByHash(record.codeHash, new Date('2026-01-01T00:00:00.000Z')),
    ).not.toBeNull();
  });

  it('deleteExpired удаляет протухший код (в т.ч. непогашенный) и возвращает счётчик', async () => {
    const record = makeRecord({ expiresAt: new Date('2026-01-01T00:00:00.000Z') });
    await store.save(record);

    const deleted = await store.deleteExpired(new Date('2026-01-01T01:00:00.000Z'));
    expect(deleted).toBe(1);
    expect(await store.deleteExpired(new Date('2026-01-01T01:00:00.000Z'))).toBe(0);
  });
});
