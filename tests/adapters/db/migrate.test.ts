import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runMigrations } from '../../../src/adapters/db/migrate.js';
import { createMemDb } from '../../helpers/pg-mem-db.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../migrations',
);

// Число файлов миграций — из каталога: новые миграции не требуют правки теста.
const migrationCount = readdirSync(migrationsDir).filter((f) => /^\d+_.*\.sql$/.test(f)).length;

describe('runMigrations на pg-mem', () => {
  it('применяет начальную миграцию и создаёт таблицы', async () => {
    const db = createMemDb();
    try {
      const applied = await runMigrations(db, migrationsDir);
      expect(applied).toBe(migrationCount);

      // Таблицы существуют и пригодны для записи/чтения.
      const id = '11111111-1111-1111-1111-111111111111';
      await db.query(
        'insert into users (id, display_name, status, created_at) values ($1, $2, $3, $4)',
        [id, 'Юрий', 'active', new Date()],
      );
      const { rows } = await db.query<{ id: string; status: string }>(
        'select id, status from users where id = $1',
        [id],
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]!.status).toBe('active');
    } finally {
      await db.close();
    }
  });

  it('идемпотентен: повторный запуск применяет 0 миграций', async () => {
    const db = createMemDb();
    try {
      const first = await runMigrations(db, migrationsDir);
      expect(first).toBe(migrationCount);
      const second = await runMigrations(db, migrationsDir);
      expect(second).toBe(0);
    } finally {
      await db.close();
    }
  });
});
