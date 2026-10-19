import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, afterAll, describe, it, expect } from 'vitest';
import { createPool, type Db } from '../../src/adapters/db/pool.js';
import { runMigrations } from '../../src/adapters/db/migrate.js';
import { PgSessionStore } from '../../src/adapters/repository/pg/pg-session-store.js';
import { pgSsoStores } from '../../src/adapters/repository/pg/pg-sso-session-store.js';
import { SsoSessionService } from '../../src/domain/sso/sso-session-service.js';
import type { Session } from '../../src/domain/sessions/session.js';
import { systemClock } from '../../src/ports/clock.js';

// A3, A5 на НАСТОЯЩЕМ PostgreSQL: изменения одной цепочки SSO браузера идут по
// очереди, а решение, чьи сессии гасить, принимается по текущему состоянию
// цепочки, а не по прежней cookie. Гонки — барьерами, без пауз.
const URL_ENV = process.env.DATABASE_URL_TEST;
const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../migrations');

function withSearchPath(url: string, schema: string): string {
  const u = new URL(url);
  u.searchParams.set('options', `-c search_path=${schema}`);
  return u.toString();
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

describe.skipIf(!URL_ENV)('Postgres: изменения цепочки SSO сериализованы', () => {
  const schema = `ssor_${randomUUID().replaceAll('-', '').slice(0, 12)}`;
  let admin: Db;
  let db: Db;

  beforeAll(async () => {
    admin = createPool(URL_ENV!);
    await admin.query(`create schema ${schema}`);
    db = createPool(withSearchPath(URL_ENV!, schema));
    await runMigrations(db, migrationsDir);
  }, 30000);

  afterAll(async () => {
    await db?.close();
    await admin?.query(`drop schema if exists ${schema} cascade`);
    await admin?.close();
  }, 30000);

  const sessions = () => new PgSessionStore(db);
  async function appSession(userId: string, ssoChainId: string): Promise<Session> {
    const now = new Date();
    const s: Session = { id: randomUUID(), userId, clientId: 'app', provider: 'email', profile: {}, scope: 'openid',
      deviceFingerprint: 'fp', ipHash: 'ip', createdAt: now, lastUsedAt: now,
      expiresAt: new Date(now.getTime() + 3600_000), revokedAt: null, ssoChainId };
    await sessions().save(s);
    return s;
  }
  const revoked = async (s: Session) => (await sessions().findById(s.id))?.revokedAt !== null;
  const liveUsers = async (chainId: string) => (await db.query<{ user_id: string }>(
    'select user_id from sso_sessions where chain_id = $1 and revoked_at is null', [chainId])).rows.map((r) => r.user_id);

  // Ждёт, пока соединение pid не встанет в ожидание блокировки.
  async function waitUntilBlocked(pid: number): Promise<void> {
    for (;;) {
      const { rows } = await admin.query<{ wait_event_type: string | null }>(
        'select wait_event_type from pg_stat_activity where pid = $1', [pid]);
      if (rows[0]?.wait_event_type === 'Lock') return;
      await new Promise((r) => setImmediate(r));
    }
  }

  // Два входа одной транзакцией каждый: оба прочитают прежнюю cookie, прежде
  // чем кто-то из них что-то запишет; первый закончивший фиксируется, только
  // когда второй уже ждёт блокировку внутри своей транзакции.
  function racingDb(): Db {
    const bothRead = deferred();
    let reads = 0;
    const pids: number[] = [];
    let finished = 0;
    const wrap = (d: Db): Db => ({
      async query<T>(sql: string, params?: unknown[]) {
        if (sql.includes('where token_hash =')) {
          const result = await d.query<T>(sql, params);
          if (++reads === 2) bothRead.resolve();
          await bothRead.promise;
          return result;
        }
        return d.query<T>(sql, params);
      },
      withTransaction: (fn) => d.withTransaction(async (tx) => {
        const { rows } = await tx.query<{ pid: number }>('select pg_backend_pid() as pid');
        const pid = rows[0]!.pid;
        pids.push(pid);
        const result = await fn(wrap(tx));
        if (++finished === 1) await waitUntilBlocked(pids.find((p) => p !== pid)!);
        return result;
      }),
      withConnection: (fn, options) => d.withConnection((conn) => fn(wrap(conn)), options),
      close: () => d.close(),
    });
    return wrap(db);
  }

  // С круга 10 смена аккаунта начинает новую цепочку: каждый из двух входов
  // получает свою, прежняя закрыта, ни в одной цепочке нет двух пользователей.
  it('A3: два входа разных пользователей с одной прежней cookie: у каждого своя новая цепочка', async () => {
    const plain = new SsoSessionService(pgSsoStores(db), systemClock, { ssoTtlSeconds: 3600 });
    const carol = randomUUID();
    const first = await plain.start(carol, { provider: 'email', loginId: randomUUID() });
    const chainId = first.session.chainId;
    const sso = new SsoSessionService(pgSsoStores(racingDb()), systemClock, { ssoTtlSeconds: 3600 });
    const alice = randomUUID();
    const bob = randomUUID();

    const [a, b] = await Promise.all([
      sso.start(alice, { provider: 'email', loginId: randomUUID() }, first.rawToken),
      sso.start(bob, { provider: 'email', loginId: randomUUID() }, first.rawToken),
    ]);

    expect(new Set([chainId, a.session.chainId, b.session.chainId]).size).toBe(3);
    expect(await liveUsers(chainId)).toEqual([]);
    expect(await liveUsers(a.session.chainId)).toEqual([alice]);
    expect(await liveUsers(b.session.chainId)).toEqual([bob]);
  });

  // Сервер не отличит задержанный запрос этого браузера от копии cookie у
  // прежнего владельца цепочки на другом устройстве. Второй не должен
  // разлогинивать вошедшего (круг 10), поэтому старая cookie ведёт только в
  // свою, прежнюю цепочку.
  it('A5: повторный вход Alice с её прежней cookie после входа Bob продолжает цепочку Alice и не трогает Bob', async () => {
    const sso = new SsoSessionService(pgSsoStores(db), systemClock, { ssoTtlSeconds: 3600 });
    const alice = randomUUID();
    const bob = randomUUID();
    const aliceFirst = await sso.start(alice, { provider: 'email', loginId: randomUUID() });
    const chainId = aliceFirst.session.chainId;
    const bobLogin = await sso.start(bob, { provider: 'email', loginId: randomUUID() }, aliceFirst.rawToken);
    const bobApp = await appSession(bob, bobLogin.session.chainId);

    const aliceAgain = await sso.start(alice, { provider: 'email', loginId: randomUUID() }, aliceFirst.rawToken);

    expect(aliceAgain.session.chainId).toBe(chainId);
    expect(await revoked(bobApp)).toBe(false);
    expect(await sso.resolve(bobLogin.rawToken)).not.toBeNull();
    expect(await liveUsers(chainId)).toEqual([alice]);
    expect(await liveUsers(bobLogin.session.chainId)).toEqual([bob]);
  });

  it('A5: повторный вход того же пользователя по текущей cookie его сессии приложений не гасит', async () => {
    const sso = new SsoSessionService(pgSsoStores(db), systemClock, { ssoTtlSeconds: 3600 });
    const alice = randomUUID();
    const first = await sso.start(alice, { provider: 'email', loginId: randomUUID() });
    const aliceApp = await appSession(alice, first.session.chainId);
    await sso.start(alice, { provider: 'email', loginId: randomUUID() }, first.rawToken);
    expect(await revoked(aliceApp)).toBe(false);
  });
});
