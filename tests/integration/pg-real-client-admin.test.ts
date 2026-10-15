import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeAll, afterAll, describe, it, expect } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createPool, type Db } from '../../src/adapters/db/pool.js';
import { runMigrations } from '../../src/adapters/db/migrate.js';
import { buildServer } from '../../src/adapters/http/server.js';
import { PgClientRegistry } from '../../src/adapters/repository/pg/pg-client-registry.js';
import { PgAuthorizationCodeStore } from '../../src/adapters/repository/pg/pg-authorization-code-store.js';
import { PgSessionStore } from '../../src/adapters/repository/pg/pg-session-store.js';
import { PgRefreshTokenStore } from '../../src/adapters/repository/pg/pg-refresh-token-store.js';
import { PgClientLock } from '../../src/adapters/repository/pg/pg-client-lock.js';
import { AuthorizationCodeService } from '../../src/domain/login/authorization-code-service.js';
import { SessionService } from '../../src/domain/sessions/session-service.js';
import { LoginService } from '../../src/domain/login/login-service.js';
import { IdentityService } from '../../src/domain/identity/identity-service.js';
import { InMemoryRateLimiter } from '../../src/adapters/ratelimit/in-memory-rate-limiter.js';
import { systemClock } from '../../src/ports/clock.js';
import type { RateLimiter } from '../../src/ports/rate-limiter.js';
import type { Client } from '../../src/domain/clients/client.js';
import { makeTestDeps, TEST_CHALLENGE, TEST_VERIFIER } from '../adapters/http/helpers.js';

// Гонки Admin API с обменом кода и параллельный старт миграций на НАСТОЯЩЕМ
// PostgreSQL. Порядок событий задают барьеры в обёртке Db и лимитере, без пауз.
const URL_ENV = process.env.DATABASE_URL_TEST;
const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../migrations');
const migrationCount = readdirSync(migrationsDir).filter((f) => /^\d+_.*\.sql$/.test(f)).length;
const ADMIN = 'pg-admin-token';

function withSearchPath(url: string, schema: string, applicationName?: string): string {
  const u = new URL(url);
  u.searchParams.set('options', `-c search_path=${schema}`);
  if (applicationName) u.searchParams.set('application_name', applicationName);
  return u.toString();
}

// Ждёт условия, проверяя его раз в 50 мс (для состояния, видимого только в БД).
async function until(check: () => Promise<boolean>): Promise<void> {
  while (!(await check())) await new Promise((resolve) => setTimeout(resolve, 50));
}

// Db, который зовёт before(sql) перед каждым запросом и after(sql) после ответа,
// в том числе внутри транзакций и выделенного соединения.
interface QueryHooks {
  before?: (sql: string) => Promise<void> | void;
  after?: (sql: string) => Promise<void> | void;
}
function hookedDb(inner: Db, hooks: QueryHooks): Db {
  return {
    async query<T>(sql: string, params?: unknown[]) {
      await hooks.before?.(sql);
      const result = await inner.query<T>(sql, params);
      await hooks.after?.(sql);
      return result;
    },
    withTransaction: (fn) => inner.withTransaction((tx) => fn(hookedDb(tx, hooks))),
    withConnection: (fn, options) => inner.withConnection((conn) => fn(hookedDb(conn, hooks)), options),
    close: () => inner.close(),
  };
}

// Ожидание условия: wait(pred) отпускает, когда pred() станет истинным после poke().
function conditions() {
  let waiters: { pred: () => boolean; resolve: () => void }[] = [];
  return {
    async wait(pred: () => boolean): Promise<void> {
      if (pred()) return;
      await new Promise<void>((resolve) => waiters.push({ pred, resolve }));
    },
    poke(): void {
      waiters = waiters.filter((w) => {
        if (!w.pred()) return true;
        w.resolve();
        return false;
      });
    },
  };
}

describe.skipIf(!URL_ENV)('Postgres: Admin API клиентов против обмена кода', () => {
  const schema = `adm_${randomUUID().replaceAll('-', '').slice(0, 12)}`;
  const appName = `app-${schema}`;
  let admin: Db;
  let db: Db;

  beforeAll(async () => {
    admin = createPool(URL_ENV!);
    await admin.query(`create schema ${schema}`);
    db = createPool(withSearchPath(URL_ENV!, schema, appName));
    await runMigrations(db, migrationsDir);
  }, 30000);

  afterAll(async () => {
    await db?.close();
    await admin?.query(`drop schema if exists ${schema} cascade`);
    await admin?.close();
  }, 30000);

  // HTTP-сервер поверх настоящих Pg-хранилищ. clientDb — Db реестра и блокировок
  // клиента (в него ставятся барьеры), rateLimiter — подменяемый.
  async function pgApp(opts: { clientDb?: Db; rateLimiter?: RateLimiter } = {}) {
    const deps = await makeTestDeps({ adminApiToken: ADMIN, clients: [] });
    const clientDb = opts.clientDb ?? db;
    const services = (d: Db) => ({
      codes: new AuthorizationCodeService(new PgAuthorizationCodeStore(d), systemClock, 60),
      sessions: new SessionService(new PgSessionStore(d), new PgRefreshTokenStore(d), deps.tokens,
        systemClock, { refreshTtlSeconds: 2592000 }),
    });
    const registry = new PgClientRegistry(clientDb);
    const shared = services(clientDb);
    Object.assign(deps, {
      clients: registry,
      adminClients: registry,
      ...shared,
      login: new LoginService(registry, new IdentityService(deps.repo), shared.codes),
      clientLock: new PgClientLock(clientDb, services),
    });
    if (opts.rateLimiter) deps.rateLimiter = opts.rateLimiter;
    const app = buildServer(deps);
    return { deps, app };
  }

  const newClient = (over: Partial<Client> = {}): Client => {
    const id = `c-${randomUUID()}`;
    return { id, type: 'internal', redirectUris: [`https://${id}.example/cb`], allowedProviders: ['email'], ...over };
  };
  const adminCall = (app: FastifyInstance, method: 'POST' | 'PATCH' | 'DELETE', url: string, payload?: object) =>
    app.inject({ method, url, headers: { authorization: `Bearer ${ADMIN}` }, ...(payload ? { payload } : {}) });
  const issue = (deps: Awaited<ReturnType<typeof pgApp>>['deps'], c: Client, provider = 'email') =>
    deps.codes.issue({ clientId: c.id, clientType: c.type, userId: randomUUID(), redirectUri: c.redirectUris[0]!,
      codeChallenge: TEST_CHALLENGE, scope: 'openid', auth: { provider, emailVerified: true } });
  const exchange = (app: FastifyInstance, c: Client, code: string) =>
    app.inject({ method: 'POST', url: '/oauth/token', payload: { grant_type: 'authorization_code', code,
      client_id: c.id, redirect_uri: c.redirectUris[0]!, code_verifier: TEST_VERIFIER } });
  async function activeSessions(clientId: string, provider?: string): Promise<number> {
    const { rows } = await db.query<{ n: string }>(
      `select count(*) as n from sessions where client_id = $1 and revoked_at is null
         and ($2::text is null or provider = $2)`,
      [clientId, provider ?? null],
    );
    return Number(rows[0]!.n);
  }

  it('R05: код, выданный до удаления клиента, не принимает клиент, заново созданный с тем же id', async () => {
    const { deps, app } = await pgApp();
    try {
      const c = newClient();
      expect((await adminCall(app, 'POST', '/admin/clients', c)).statusCode).toBe(201);
      const code = await issue(deps, c);
      expect((await adminCall(app, 'DELETE', `/admin/clients/${c.id}`)).statusCode).toBe(204);
      expect((await adminCall(app, 'POST', '/admin/clients', c)).statusCode).toBe(201);
      const res = await exchange(app, c, code);
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe('invalid_grant');
      expect(await activeSessions(c.id)).toBe(0);
    } finally { await app.close(); }
  });

  it('R05: код, записанный после удаления (вход проверил клиента до DELETE), не принимает новая регистрация', async () => {
    const { deps, app } = await pgApp();
    try {
      const c = newClient();
      expect((await adminCall(app, 'POST', '/admin/clients', c)).statusCode).toBe(201);
      expect((await adminCall(app, 'DELETE', `/admin/clients/${c.id}`)).statusCode).toBe(204);
      const late = await issue(deps, c);
      expect((await adminCall(app, 'POST', '/admin/clients', c)).statusCode).toBe(201);
      expect((await exchange(app, c, late)).statusCode).toBe(400);
      // Код, выданный уже новой регистрации, работает.
      expect((await exchange(app, c, await issue(deps, c))).statusCode).toBe(200);
    } finally { await app.close(); }
  });

  it('P3-2: лимит обмена кода проверяется вне транзакции и без блокировки клиента', async () => {
    const seen: { clientLocked: boolean; openTransactions: number }[] = [];
    let clientId = '';
    const inner = new InMemoryRateLimiter(systemClock);
    const rateLimiter: RateLimiter = {
      async hit(key, limit, windowSeconds) {
        if (key.startsWith('token-user:')) {
          const clientLocked = await admin.withTransaction(async (tx) => {
            try {
              await tx.query(`select id from ${schema}.clients where id = $1 for update nowait`, [clientId]);
              return false;
            } catch (err) {
              if ((err as { code?: string }).code === '55P03') return true;
              throw err;
            }
          });
          const { rows } = await admin.query<{ n: string }>(
            `select count(*) as n from pg_stat_activity where application_name = $1 and state like 'idle in transaction%'`,
            [appName],
          );
          seen.push({ clientLocked, openTransactions: Number(rows[0]!.n) });
        }
        return inner.hit(key, limit, windowSeconds);
      },
      close: async () => {},
    };
    const { deps, app } = await pgApp({ rateLimiter });
    try {
      const c = newClient();
      clientId = c.id;
      expect((await adminCall(app, 'POST', '/admin/clients', c)).statusCode).toBe(201);
      expect((await exchange(app, c, await issue(deps, c))).statusCode).toBe(200);
      expect(seen).toEqual([{ clientLocked: false, openTransactions: 0 }]);
    } finally { await app.close(); }
  });

  it('P3-4: старая версия без client_type продолжает записывать коды; такой код считается internal', async () => {
    const c = newClient({ type: 'external' });
    await new PgClientRegistry(db).create(c);
    const id = randomUUID();
    // Запись кода так, как её делает версия до миграций 0011 и 0012.
    await db.query(
      `insert into authorization_codes
         (id, code_hash, client_id, user_id, redirect_uri, code_challenge, scope, nonce, auth, expires_at, consumed_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [id, `old-${id}`, c.id, randomUUID(), c.redirectUris[0], TEST_CHALLENGE, 'openid', null,
        JSON.stringify({ provider: 'email' }), new Date(Date.now() + 60_000), null],
    );
    const { rows } = await db.query<{ client_type: string }>(
      'select client_type from authorization_codes where id = $1', [id]);
    expect(rows[0]!.client_type).toBe('internal');
  });

  it('R06: обмен кода, прошедший проверку политики, не оставляет живой сессии запрещённого провайдера после PATCH', async () => {
    const events = conditions();
    let atSessionWrite = false;
    let released = false;
    const release = () => { released = true; events.poke(); };
    // Обмен проверил политику и стоит перед записью сессии, пока PATCH не
    // запросит исключительную блокировку клиента (или не завершится). Дальше
    // держать обмен нельзя: правильная реализация ждёт его под той же блокировкой.
    const clientDb = hookedDb(db, {
      async before(sql) {
        if (/for update/i.test(sql)) release();
        if (atSessionWrite || !/insert into sessions/i.test(sql)) return;
        atSessionWrite = true;
        events.poke();
        await events.wait(() => released);
      },
    });
    const { deps, app } = await pgApp({ clientDb });
    try {
      const c = newClient({ allowedProviders: ['email', 'google'] });
      expect((await adminCall(app, 'POST', '/admin/clients', c)).statusCode).toBe(201);
      const code = await issue(deps, c, 'email');
      const exchanging = exchange(app, c, code);
      await events.wait(() => atSessionWrite);
      const patching = adminCall(app, 'PATCH', `/admin/clients/${c.id}`, { allowedProviders: ['google'] })
        .finally(release);
      const [patched] = await Promise.all([patching, exchanging]);
      expect(patched.statusCode).toBe(200);
      expect(await activeSessions(c.id, 'email')).toBe(0);
    } finally { await app.close(); }
  });

  it('R09: код тихого входа, решённого без согласия для internal, не обменивается, если до записи кода клиент стал external', async () => {
    const events = conditions();
    let armed = false;
    let authorizeRead = false;
    let patchDone = false;
    // Тихий вход прочитал клиента (internal: согласие не нужно) и ждёт, пока
    // PATCH сделает клиента external; только потом записывает код.
    const clientDb = hookedDb(db, {
      after: async (sql) => {
        if (!armed || authorizeRead || !/from clients\s+where id = \$1$/i.test(sql.trim())) return;
        authorizeRead = true;
        events.poke();
        await events.wait(() => patchDone);
      },
    });
    const { deps, app } = await pgApp({ clientDb });
    try {
      const c = newClient();
      expect((await adminCall(app, 'POST', '/admin/clients', c)).statusCode).toBe(201);
      const { rawToken } = await deps.sso.start(randomUUID(), { provider: 'email', email: 'u@example.com', emailVerified: true });
      armed = true;
      const silent = app.inject({ method: 'GET', headers: { cookie: `sso=${rawToken}` }, url: `/authorize?${new URLSearchParams({
        client_id: c.id, redirect_uri: c.redirectUris[0]!, response_type: 'code', scope: 'openid',
        code_challenge: TEST_CHALLENGE, code_challenge_method: 'S256', state: 'st', prompt: 'none',
      }).toString()}` });
      await events.wait(() => authorizeRead);
      const patched = await adminCall(app, 'PATCH', `/admin/clients/${c.id}`, { type: 'external' });
      expect(patched.statusCode).toBe(200);
      patchDone = true;
      events.poke();
      const redirect = await silent;
      armed = false;
      const location = new URL(String(redirect.headers.location));
      const code = location.searchParams.get('code');
      // Либо код не выдан вовсе, либо обмен его отклоняет.
      if (code !== null) {
        const res = await exchange(app, c, code);
        expect(res.statusCode).toBe(400);
        expect(res.json().error).toBe('invalid_grant');
      }
      expect(await activeSessions(c.id)).toBe(0);
    } finally { await app.close(); }
  });

  it('R07: два одновременных PATCH не дают external-клиенту Google', async () => {
    const events = conditions();
    let armed = false;
    let reads = 0;
    let lockRequests = 0;
    // Первое прочитанное каждым PATCH состояние клиента ждёт, пока прочитает и
    // второй. Исключение — второй уже ждёт исключительной блокировки клиента:
    // тогда он прочитает только итог первого.
    const clientDb = hookedDb(db, {
      before: (sql) => {
        if (!armed || !/for update/i.test(sql)) return;
        lockRequests += 1;
        events.poke();
      },
      after: async (sql) => {
        if (!armed || !/from clients\s+where id = \$1/i.test(sql)) return;
        reads += 1;
        if (reads > 2) return;
        events.poke();
        await events.wait(() => reads >= 2 || lockRequests >= 2);
      },
    });
    const { app } = await pgApp({ clientDb });
    try {
      const c = newClient();
      expect((await adminCall(app, 'POST', '/admin/clients', c)).statusCode).toBe(201);
      armed = true;
      const results = await Promise.all([
        adminCall(app, 'PATCH', `/admin/clients/${c.id}`, { type: 'external' }),
        adminCall(app, 'PATCH', `/admin/clients/${c.id}`, { allowedProviders: ['email', 'google'] }),
      ]);
      armed = false;
      expect(results.map((r) => r.statusCode).sort()).toEqual([200, 400]);
      const stored = await new PgClientRegistry(db).findClient(c.id);
      expect(stored!.type === 'external' && stored!.allowedProviders.includes('google')).toBe(false);
    } finally { await app.close(); }
  });
});

describe.skipIf(!URL_ENV)('Postgres: одновременный старт двух копий с миграциями', () => {
  let admin: Db;
  const replicas: Db[] = [];
  const schemas: string[] = [];

  // Пустая схема на тест: каждая проверка стартует с непримененными миграциями.
  async function freshSchema(): Promise<string> {
    const schema = `mig_${randomUUID().replaceAll('-', '').slice(0, 12)}`;
    await admin.query(`create schema ${schema}`);
    schemas.push(schema);
    return schema;
  }

  beforeAll(() => {
    admin = createPool(URL_ENV!);
  });

  afterAll(async () => {
    for (const r of replicas) await r.close();
    for (const schema of schemas) await admin?.query(`drop schema if exists ${schema} cascade`);
    await admin?.close();
  });

  it('P3-3: вторая копия ждёт блокировку миграций дольше лимитов запроса и не падает', async () => {
    const schema = await freshSchema();
    const limits = { statementTimeoutMs: 300, queryTimeoutMs: 600 };
    const second = `mig-b-${randomUUID()}`;
    const events = conditions();
    let firstHolds = false;
    let secondFinished = false;
    let secondWaitedLong = false;
    const first = hookedDb(createPool(withSearchPath(URL_ENV!, schema), undefined, limits), {
      async after(sql) {
        if (firstHolds || !/select version from schema_migrations/i.test(sql)) return;
        // Первая копия держит блокировку, пока вторая не прождёт её дольше обоих лимитов.
        firstHolds = true;
        events.poke();
        await events.wait(() => secondWaitedLong || secondFinished);
      },
    });
    const late = createPool(withSearchPath(URL_ENV!, schema, second), undefined, limits);
    replicas.push(first, late);
    const firstRun = runMigrations(first, migrationsDir);
    await events.wait(() => firstHolds);
    const secondRun = runMigrations(late, migrationsDir).finally(() => { secondFinished = true; events.poke(); });
    void until(async () => {
      if (secondFinished) return true;
      const { rows } = await admin.query<{ n: string }>(
        `select count(*) as n from pg_stat_activity where application_name = $1
            and wait_event_type = 'Lock' and now() - query_start > interval '1500 milliseconds'`,
        [second],
      );
      return Number(rows[0]!.n) > 0;
    }).then(() => { secondWaitedLong = true; events.poke(); });
    const results = await Promise.allSettled([firstRun, secondRun]);
    expect(results.map((r) => r.status)).toEqual(['fulfilled', 'fulfilled']);
    expect(secondWaitedLong).toBe(true);
  }, 30000);

  it('R13: обе копии стартуют, каждая миграция применена ровно один раз', async () => {
    const schema = await freshSchema();
    const events = conditions();
    const state = [0, 1].map(() => ({ started: false, lockRequested: false, read: false, finished: false }));
    const hooks = (i: number): QueryHooks => {
      const me = state[i]!;
      const other = state[1 - i]!;
      return {
        async before(sql) {
          if (/pg_advisory_lock\(/i.test(sql)) me.lockRequested = true;
          if (me.started) return;
          // Обе копии начинают одновременно.
          me.started = true;
          events.poke();
          await events.wait(() => other.started);
        },
        async after(sql) {
          if (!/select version from schema_migrations/i.test(sql)) return;
          // Список применённых прочитали обе, если только вторая не ждёт общей блокировки.
          me.read = true;
          events.poke();
          await events.wait(() => other.read || other.lockRequested || other.finished);
        },
      };
    };
    const copies = [0, 1].map((i) => hookedDb(createPool(withSearchPath(URL_ENV!, schema)), hooks(i)));
    replicas.push(...copies);
    const results = await Promise.allSettled(copies.map((r, i) =>
      runMigrations(r, migrationsDir).finally(() => { state[i]!.finished = true; events.poke(); })));
    expect(results.map((r) => r.status)).toEqual(['fulfilled', 'fulfilled']);
    const applied = results.map((r) => (r as PromiseFulfilledResult<number>).value);
    expect(applied[0]! + applied[1]!).toBe(migrationCount);
    const { rows } = await admin.query<{ n: string }>(`select count(*) as n from ${schema}.schema_migrations`);
    expect(Number(rows[0]!.n)).toBe(migrationCount);
  }, 30000);
});
