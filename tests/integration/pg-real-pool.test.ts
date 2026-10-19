import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createPool, type Db } from '../../src/adapters/db/pool.js';

// T05: обрыв выданного соединения (рестарт Postgres, сеть, pg_terminate_backend)
// посреди withTransaction/withConnection не роняет процесс: текущая операция
// завершается ошибкой, соединение уходит из пула, пул продолжает работать.
// Барьер — сообщение пула об ошибке соединения (onError), без пауз.
const URL_ENV = process.env.DATABASE_URL_TEST;

describe.skipIf(!URL_ENV)('Postgres: обрыв выданного соединения', () => {
  let admin: Db;
  beforeAll(() => { admin = createPool(URL_ENV!); });
  afterAll(async () => { await admin?.close(); });

  // Пул, который сообщает об ошибках соединений; nextError ждёт следующую —
  // или непойманное исключение процесса (так выглядит обрыв без обработчика).
  let notify: ((err: unknown) => void) | undefined;
  const uncaught: unknown[] = [];
  const onUncaught = (err: unknown) => { uncaught.push(err); notify?.(err); };
  beforeAll(() => { process.on('uncaughtException', onUncaught); });
  afterAll(() => { process.off('uncaughtException', onUncaught); });
  function poolWithErrorBarrier() {
    const errors: Error[] = [];
    const db = createPool(URL_ENV!, (err) => { errors.push(err); notify?.(err); });
    const nextError = () => new Promise<unknown>((resolve) => { notify = resolve; });
    return { db, errors, nextError };
  }

  // Обрывает соединение, на котором выполняется conn, и ждёт, пока клиент узнает об обрыве.
  async function killOwnBackend(conn: Db, nextError: () => Promise<unknown>): Promise<void> {
    const { rows } = await conn.query<{ pid: number }>('select pg_backend_pid() as pid');
    const noticed = nextError();
    await admin.query('select pg_terminate_backend($1)', [rows[0]!.pid]);
    await noticed;
  }

  for (const method of ['withTransaction', 'withConnection'] as const) {
    it(`${method}: обрыв между запросами — операция падает, процесс жив, пул работает`, async () => {
      const { db, errors, nextError } = poolWithErrorBarrier();
      uncaught.length = 0;
      try {
        const run = db[method](async (conn) => {
          await killOwnBackend(conn, nextError);
          await conn.query('select 1');
          return 'не должно дойти';
        });
        await expect(run).rejects.toThrow();
        expect(uncaught).toEqual([]);
        expect(errors.length).toBeGreaterThan(0);
        // Сломанное соединение не вернулось в пул: следующие запросы идут.
        for (let i = 0; i < 3; i++) {
          expect((await db.query<{ ok: number }>('select 1 as ok')).rows[0]!.ok).toBe(1);
          expect(await db.withTransaction(async (tx) => (await tx.query<{ ok: number }>('select 2 as ok')).rows[0]!.ok)).toBe(2);
        }
      } finally {
        await db.close();
      }
    });
  }

  it('withConnection: обрыв во время транзакции внутри выделенного соединения', async () => {
    const { db, nextError } = poolWithErrorBarrier();
    uncaught.length = 0;
    try {
      const run = db.withConnection((conn) => conn.withTransaction(async (tx) => {
        await killOwnBackend(tx, nextError);
        await tx.query('select 1');
      }));
      await expect(run).rejects.toThrow();
      expect(uncaught).toEqual([]);
      expect((await db.query<{ ok: number }>('select 1 as ok')).rows[0]!.ok).toBe(1);
    } finally {
      await db.close();
    }
  });
});
