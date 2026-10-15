import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { createMemDb } from '../../../helpers/pg-mem-db.js';
import { runMigrations } from '../../../../src/adapters/db/migrate.js';
import type { Db } from '../../../../src/adapters/db/pool.js';
import type { EmailSecretRecord } from '../../../../src/domain/email-secret/email-secret.js';
import { PgEmailSecretStore } from '../../../../src/adapters/repository/pg/pg-email-secret-store.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../migrations',
);

function makeRecord(
  overrides: Partial<EmailSecretRecord> = {},
): EmailSecretRecord {
  return {
    id: randomUUID(),
    purpose: 'email-code-login',
    email: 'user@example.com',
    secretHash: `hash-${randomUUID()}`,
    expiresAt: new Date('2026-01-01T01:00:00.000Z'),
    consumedAt: null,
    ...overrides,
  };
}

const NOW = new Date('2026-01-01T00:00:00.000Z');

describe('PgEmailSecretStore на pg-mem', () => {
  let db: Db;
  let store: PgEmailSecretStore;

  beforeEach(async () => {
    db = createMemDb();
    await runMigrations(db, migrationsDir);
    store = new PgEmailSecretStore(db);
  });

  afterEach(async () => {
    await db.close();
  });

  it('save -> findActive round-trip', async () => {
    const record = makeRecord();
    await store.save(record);

    expect(await store.findActive(record.purpose, record.email, NOW)).toEqual(record);
  });

  it('при нескольких активных findActive возвращает свежайший (по expires_at)', async () => {
    const older = makeRecord({ expiresAt: new Date('2026-01-01T00:30:00.000Z') });
    const newer = makeRecord({ expiresAt: new Date('2026-01-01T02:00:00.000Z') });
    await store.save(older);
    await store.save(newer);

    const found = await store.findActive('email-code-login', 'user@example.com', NOW);
    expect(found?.id).toBe(newer.id);
  });

  it('findActive не находит истёкший', async () => {
    const record = makeRecord({ expiresAt: new Date('2026-01-01T00:00:00.000Z') });
    await store.save(record);

    expect(
      await store.findActive(record.purpose, record.email, new Date('2026-01-01T02:00:00.000Z')),
    ).toBeNull();
  });

  it('findActive не находит погашенный', async () => {
    const record = makeRecord();
    await store.save(record);
    await store.consume(record.id, new Date('2026-01-01T00:30:00.000Z'));

    expect(await store.findActive(record.purpose, record.email, NOW)).toBeNull();
  });

  it('consume первый раз -> true, повтор -> false (CAS)', async () => {
    const record = makeRecord();
    await store.save(record);

    expect(await store.consume(record.id, new Date('2026-01-01T00:30:00.000Z'))).toBe(true);
    expect(await store.consume(record.id, new Date('2026-01-01T00:40:00.000Z'))).toBe(false);
  });

  it('invalidateActive гасит все активные для пары, но не трогает другую пару', async () => {
    const a1 = makeRecord();
    const a2 = makeRecord({ expiresAt: new Date('2026-01-01T02:00:00.000Z') });
    const otherEmail = makeRecord({ email: 'other@example.com' });
    const otherPurpose = makeRecord({ purpose: 'email-verify' });
    await store.save(a1);
    await store.save(a2);
    await store.save(otherEmail);
    await store.save(otherPurpose);

    await store.invalidateActive('email-code-login', 'user@example.com', new Date('2026-01-01T00:15:00.000Z'));

    expect(await store.findActive('email-code-login', 'user@example.com', NOW)).toBeNull();
    expect(await store.findActive('email-code-login', 'other@example.com', NOW)).not.toBeNull();
    expect(await store.findActive('email-verify', 'user@example.com', NOW)).not.toBeNull();
  });

  it('deleteExpired не трогает живой секрет', async () => {
    const record = makeRecord({ expiresAt: new Date('2026-01-01T01:00:00.000Z') });
    await store.save(record);

    const deleted = await store.deleteExpired(NOW);
    expect(deleted).toBe(0);
    expect(await store.findActive(record.purpose, record.email, NOW)).not.toBeNull();
  });

  it('deleteExpired удаляет протухший секрет (в т.ч. непогашенный) и возвращает счётчик', async () => {
    const record = makeRecord({ expiresAt: new Date('2026-01-01T00:00:00.000Z') });
    await store.save(record);

    const deleted = await store.deleteExpired(new Date('2026-01-01T01:00:00.000Z'));
    expect(deleted).toBe(1);
    expect(await store.deleteExpired(new Date('2026-01-01T01:00:00.000Z'))).toBe(0);
  });
});
