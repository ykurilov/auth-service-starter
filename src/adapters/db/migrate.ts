import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Db } from './pool.js';

// Файл миграции: NNNN_описание.sql. Номер (version) — числовой префикс.
interface Migration {
  version: number;
  file: string;
}

async function loadMigrations(dir: string): Promise<Migration[]> {
  const entries = await readdir(dir);
  const migrations: Migration[] = [];
  for (const file of entries) {
    const match = /^(\d+)_.*\.sql$/.exec(file);
    if (!match) continue;
    migrations.push({ version: Number.parseInt(match[1]!, 10), file });
  }
  migrations.sort((a, b) => a.version - b.version);
  return migrations;
}

// Ключ сессионной advisory-блокировки миграций (пара int4: «сервис», «миграции»).
// Ключи-пары не пересекаются с bigint-ключами pg_advisory_xact_lock входа.
const MIGRATIONS_LOCK = [0x41555448, 1] as const;

// Применяет непринятые миграции из dir по порядку версий, каждую в своей
// транзакции. Идемпотентно: уже принятые (в schema_migrations) пропускаются.
// Копии сервиса, стартующие одновременно, ждут друг друга на общей блокировке:
// вторая видит миграции первой и применяет только недостающие. Ни ожидание,
// ни сами миграции не ограничены пределами обычного запроса: долгая миграция
// первой копии не роняет вторую по таймауту.
// Возвращает число применённых миграций.
export async function runMigrations(db: Db, dir: string): Promise<number> {
  return db.withConnection(async (conn) => {
    await conn.query('select pg_advisory_lock($1::int, $2::int)', [...MIGRATIONS_LOCK]);
    try {
      return await applyPending(conn, dir);
    } finally {
      await conn.query('select pg_advisory_unlock($1::int, $2::int)', [...MIGRATIONS_LOCK]);
    }
  }, { withoutQueryLimits: true });
}

async function applyPending(db: Db, dir: string): Promise<number> {
  await db.query(
    `create table if not exists schema_migrations (
       version int primary key,
       applied_at timestamptz not null
     )`,
  );

  const applied = await db.query<{ version: number }>(
    'select version from schema_migrations',
  );
  const done = new Set(applied.rows.map((r) => Number(r.version)));

  const migrations = await loadMigrations(dir);
  let count = 0;
  for (const migration of migrations) {
    if (done.has(migration.version)) continue;
    const sql = await readFile(path.join(dir, migration.file), 'utf8');
    await db.withTransaction(async (tx) => {
      await tx.query(sql);
      await tx.query(
        'insert into schema_migrations (version, applied_at) values ($1, $2)',
        [migration.version, new Date()],
      );
    });
    count += 1;
  }
  return count;
}
