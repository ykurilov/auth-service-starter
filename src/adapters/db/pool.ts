import pg from 'pg';

// Тонкая абстракция над драйвером БД: доменные адаптеры зависят только от Db,
// не от конкретного pg.Pool. Это упрощает тестирование (pg-mem реализует тот же
// интерфейс) и изолирует детали драйвера.
export interface Db {
  query<T = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: T[]; rowCount: number }>;
  withTransaction<T>(fn: (tx: Db) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

// Db поверх одного клиента внутри транзакции. Вложенный withTransaction не
// открывает новый BEGIN — работает в уже открытой транзакции (без savepoint'ов).
function clientDb(client: pg.PoolClient): Db {
  return {
    async query<T = Record<string, unknown>>(sql: string, params?: unknown[]) {
      const result = await client.query(sql, params);
      return { rows: result.rows as T[], rowCount: result.rowCount ?? 0 };
    },
    async withTransaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
      return fn(clientDb(client));
    },
    async close(): Promise<void> {
      // Клиент освобождается владельцем транзакции (release в finally), не здесь.
    },
  };
}

// Db поверх пула. query берёт свободного клиента из пула; withTransaction —
// выделенного клиента с BEGIN/COMMIT/ROLLBACK.
export function createPool(databaseUrl: string, onError?: (err: Error) => void): Db {
  const pool = new pg.Pool({ connectionString: databaseUrl, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 30_000, statement_timeout: 15_000, query_timeout: 20_000 });
  // Без слушателя 'error' обрыв idle-соединения (рестарт Postgres, сеть)
  // валит весь процесс. Пул сам пересоздаст соединение — достаточно лога.
  pool.on('error', (err) => onError?.(err));
  return {
    async query<T = Record<string, unknown>>(sql: string, params?: unknown[]) {
      const result = await pool.query(sql, params);
      return { rows: result.rows as T[], rowCount: result.rowCount ?? 0 };
    },
    async withTransaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      let releaseError: Error | undefined;
      try {
        await client.query('BEGIN');
        const value = await fn(clientDb(client));
        await client.query('COMMIT');
        return value;
      } catch (err) {
        try { await client.query('ROLLBACK'); }
        catch (rollbackError) { releaseError = rollbackError instanceof Error ? rollbackError : new Error('ROLLBACK failed'); }
        throw err;
      } finally {
        client.release(releaseError);
      }
    },
    async close(): Promise<void> {
      await pool.end();
    },
  };
}
