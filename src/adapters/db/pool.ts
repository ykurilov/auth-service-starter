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
  // Одно соединение на всё время fn: для сессионных advisory-блокировок.
  // Транзакции внутри fn идут по одной на этом же соединении.
  withConnection<T>(fn: (conn: Db) => Promise<T>, options?: ConnectionOptions): Promise<T>;
  close(): Promise<void>;
}

export interface ConnectionOptions {
  // Снять пределы запроса (QueryLimits) на время fn: миграции и ожидание их
  // блокировки законно идут дольше обычного запроса. Потом пределы
  // восстанавливаются, и соединение возвращается в пул прежним.
  withoutQueryLimits?: boolean;
}

// Отправка запроса на конкретном соединении (со своим пределом в драйвере).
type Send = (sql: string, params?: unknown[]) => Promise<pg.QueryResult>;

// Самая большая задержка таймера Node.js: драйвер не умеет выключать
// query_timeout у отдельного запроса, поэтому «без предела» — это ~24 дня.
const NO_QUERY_TIMEOUT_MS = 2_147_483_647;

function sendOn(client: pg.PoolClient, withoutQueryLimits = false): Send {
  return withoutQueryLimits
    ? (sql, params) => {
        // query_timeout отдельного запроса драйвер читает, но в типах его нет.
        const config: pg.QueryConfig & { query_timeout: number } =
          { text: sql, values: params, query_timeout: NO_QUERY_TIMEOUT_MS };
        return client.query(config);
      }
    : (sql, params) => client.query(sql, params);
}

// Db поверх одного клиента внутри транзакции. Вложенный withTransaction не
// открывает новый BEGIN — работает в уже открытой транзакции (без savepoint'ов).
function clientDb(send: Send): Db {
  return {
    async query<T = Record<string, unknown>>(sql: string, params?: unknown[]) {
      const result = await send(sql, params);
      return { rows: result.rows as T[], rowCount: result.rowCount ?? 0 };
    },
    async withTransaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
      return fn(clientDb(send));
    },
    async withConnection<T>(fn: (conn: Db) => Promise<T>): Promise<T> {
      return fn(clientDb(send));
    },
    async close(): Promise<void> {
      // Клиент освобождается владельцем транзакции (release в finally), не здесь.
    },
  };
}

// BEGIN/COMMIT/ROLLBACK на данном клиенте. Возвращает ошибку ROLLBACK, если
// откатить не удалось: такого клиента нельзя возвращать в пул.
async function inTransaction<T>(
  send: Send,
  fn: (tx: Db) => Promise<T>,
): Promise<{ value: T } | { error: unknown; broken?: Error }> {
  try {
    await send('BEGIN');
    const value = await fn(clientDb(send));
    await send('COMMIT');
    return { value };
  } catch (error) {
    try {
      await send('ROLLBACK');
      return { error };
    } catch (rollbackError) {
      return { error, broken: rollbackError instanceof Error ? rollbackError : new Error('ROLLBACK failed') };
    }
  }
}

// Db поверх выделенного клиента вне транзакции: каждый withTransaction — свой
// BEGIN/COMMIT на этом же соединении. Сломанный откат помечает соединение,
// чтобы владелец не вернул его в пул.
function connectionDb(send: Send, markBroken: (err: Error) => void): Db {
  return {
    ...clientDb(send),
    async withTransaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
      const result = await inTransaction(send, fn);
      if ('value' in result) return result.value;
      if (result.broken) markBroken(result.broken);
      throw result.error;
    },
    async withConnection<T>(fn: (conn: Db) => Promise<T>): Promise<T> {
      return fn(connectionDb(send, markBroken));
    },
  };
}

// Пределы одного запроса: на сервере (statement_timeout) и в драйвере
// (query_timeout). Защищают обработчики запросов от зависшей БД.
export interface QueryLimits {
  statementTimeoutMs: number;
  queryTimeoutMs: number;
}
const DEFAULT_LIMITS: QueryLimits = { statementTimeoutMs: 15_000, queryTimeoutMs: 20_000 };

// Db поверх пула. query берёт свободного клиента из пула; withTransaction —
// выделенного клиента с BEGIN/COMMIT/ROLLBACK.
export function createPool(
  databaseUrl: string,
  onError?: (err: Error) => void,
  limits: QueryLimits = DEFAULT_LIMITS,
): Db {
  const pool = new pg.Pool({ connectionString: databaseUrl, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 30_000,
    statement_timeout: limits.statementTimeoutMs, query_timeout: limits.queryTimeoutMs });
  // Без слушателя 'error' обрыв idle-соединения (рестарт Postgres, сеть)
  // валит весь процесс. Пул сам пересоздаст соединение — достаточно лога.
  pool.on('error', (err) => onError?.(err));

  // Выданный клиент пул не слушает: на время владения ставим свой обработчик
  // 'error', иначе обрыв посреди withTransaction/withConnection валит процесс.
  // Оборванное или сломанное соединение release уничтожает, а не возвращает
  // в пул; текущая операция падает на следующем запросе.
  async function checkout() {
    const client = await pool.connect();
    let broken: Error | undefined;
    const onClientError = (err: Error) => {
      broken ??= err;
      onError?.(err);
    };
    client.on('error', onClientError);
    return {
      client,
      markBroken(err: Error) { broken ??= err; },
      release() {
        client.off('error', onClientError);
        client.release(broken);
      },
    };
  }
  return {
    async query<T = Record<string, unknown>>(sql: string, params?: unknown[]) {
      const result = await pool.query(sql, params);
      return { rows: result.rows as T[], rowCount: result.rowCount ?? 0 };
    },
    async withTransaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
      const lease = await checkout();
      try {
        const result = await inTransaction(sendOn(lease.client), fn);
        if ('broken' in result && result.broken) lease.markBroken(result.broken);
        if ('value' in result) return result.value;
        throw result.error;
      } finally {
        lease.release();
      }
    },
    async withConnection<T>(fn: (conn: Db) => Promise<T>, options?: ConnectionOptions): Promise<T> {
      const lease = await checkout();
      const unlimited = options?.withoutQueryLimits ?? false;
      const send = sendOn(lease.client, unlimited);
      try {
        if (unlimited) await send('set statement_timeout = 0');
        const value = await fn(connectionDb(send, lease.markBroken));
        // RESET возвращает предел, заданный пулом при подключении.
        if (unlimited) await send('reset statement_timeout');
        return value;
      } catch (err) {
        // Состояние соединения после сбоя неизвестно (в том числе удержанные
        // сессионные блокировки): закрываем его, а не возвращаем в пул.
        lease.markBroken(err instanceof Error ? err : new Error('connection failed'));
        throw err;
      } finally {
        lease.release();
      }
    },
    async close(): Promise<void> {
      await pool.end();
    },
  };
}
