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

// Применяет непринятые миграции из dir по порядку версий, каждую в своей
// транзакции. Идемпотентно: уже принятые (в schema_migrations) пропускаются.
// Возвращает число применённых миграций.
export async function runMigrations(db: Db, dir: string): Promise<number> {
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
