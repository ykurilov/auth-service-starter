import { randomUUID } from 'node:crypto';
import { DataType, newDb, type IMemoryDb } from 'pg-mem';
import type { Db } from '../../src/adapters/db/pool.js';

// pg-mem не знает advisory-блокировок Postgres и gen_random_uuid: регистрируем
// заглушки, чтобы тот же SQL выполнялся. Это НЕ блокировка и НЕ доказывает
// сериализацию, а ROLLBACK в pg-mem не откатывает записи — конкуренцию и откат
// проверяют тесты на настоящем Postgres (tests/integration/pg-real*, DATABASE_URL_TEST).
export function registerPgStubs(mem: IMemoryDb): void {
  mem.public.registerFunction({
    name: 'pg_advisory_xact_lock',
    args: [DataType.bigint],
    returns: DataType.text,
    implementation: () => null,
    impure: true,
  });
  for (const name of ['pg_advisory_lock', 'pg_advisory_unlock']) {
    mem.public.registerFunction({
      name,
      args: [DataType.integer, DataType.integer],
      returns: DataType.text,
      implementation: () => null,
      impure: true,
    });
  }
  mem.public.registerFunction({
    name: 'gen_random_uuid',
    returns: DataType.uuid,
    implementation: () => randomUUID(),
    impure: true,
  });
}

// In-memory реализация Db на pg-mem — тот же интерфейс, что и createPool, но без
// реального PostgreSQL. Оборачиваем pg-mem-совместимый Pool так же, как боевой пул.
export function createMemDb(): Db {
  // noAstCoverageCheck: pg-mem по умолчанию бросает, если query-planner не
  // «прочитал» части AST (например, несколько DDL-операторов в одном query).
  // Наш SQL миграции — многооператорный; для теста отключаем эту проверку.
  const mem = newDb({ noAstCoverageCheck: true });
  registerPgStubs(mem);
  const pg = mem.adapters.createPg();
  const pool = new pg.Pool();

  function clientDb(client: {
    query: (sql: string, params?: unknown[]) => Promise<{ rows: unknown[]; rowCount: number }>;
  }): Db {
    return {
      async query<T = Record<string, unknown>>(sql: string, params?: unknown[]) {
        const result = await client.query(sql, params);
        return { rows: result.rows as T[], rowCount: result.rowCount ?? 0 };
      },
      async withTransaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
        return fn(clientDb(client));
      },
      async withConnection<T>(fn: (conn: Db) => Promise<T>): Promise<T> {
        return fn(clientDb(client));
      },
      async close(): Promise<void> {
        // Владелец транзакции освобождает клиента.
      },
    };
  }

  const db: Db = {
    async query<T = Record<string, unknown>>(sql: string, params?: unknown[]) {
      const result = await pool.query(sql, params);
      return { rows: result.rows as T[], rowCount: result.rowCount ?? 0 };
    },
    // Соединения pg-mem общие: отдельное соединение не нужно.
    async withConnection<T>(fn: (conn: Db) => Promise<T>): Promise<T> {
      return fn(db);
    },
    async withTransaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const value = await fn(clientDb(client));
        await client.query('COMMIT');
        return value;
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
    },
    async close(): Promise<void> {
      await pool.end();
    },
  };
  return db;
}
