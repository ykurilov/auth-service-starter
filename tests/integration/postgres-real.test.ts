import { randomUUID } from 'node:crypto';
import { beforeAll, afterAll, describe, it, expect } from 'vitest';
import { createPool, type Db } from '../../src/adapters/db/pool.js';
import { runMigrations } from '../../src/adapters/db/migrate.js';
import { PgSessionStore } from '../../src/adapters/repository/pg/pg-session-store.js';
import { PgRefreshTokenStore } from '../../src/adapters/repository/pg/pg-refresh-token-store.js';
import { PgClientRegistry } from '../../src/adapters/repository/pg/pg-client-registry.js';
import { PgIdentityRepository } from '../../src/adapters/repository/pg/pg-identity-repository.js';
import { IdentityService } from '../../src/domain/identity/identity-service.js';
import { SessionService } from '../../src/domain/sessions/session-service.js';
import { TokenService } from '../../src/domain/tokens/token-service.js';
import { loadSigningKey } from '../../src/domain/tokens/signing-key.js';
import { advanceableClock } from '../helpers/advanceable-clock.js';
import { sha256Hex } from '../../src/domain/shared/hash.js';
import type { RefreshTokenStore } from '../../src/domain/sessions/refresh-token.js';

// Укажите отдельную тестовую БД. Каждый прогон использует собственную schema.
describe.skipIf(!process.env.DATABASE_URL_TEST)('real PostgreSQL transactions and concurrency', () => {
  let admin: Db;
  let db: Db;
  let tokens: TokenService;
  const schema = 'auth_test_' + randomUUID().replaceAll('-', '');
  const clock = advanceableClock(new Date());
  const create = (store: RefreshTokenStore = new PgRefreshTokenStore(db)) =>
    new SessionService(new PgSessionStore(db), store, tokens, clock, { refreshTtlSeconds: 2592000 });
  const start = () => ({ userId: randomUUID(), clientId: 'test-app', provider: 'email', profile: {}, scope: 'openid', device: {} });

  beforeAll(async () => {
    admin = createPool(process.env.DATABASE_URL_TEST!);
    await admin.query(`create schema ${schema}`);
    const url = new URL(process.env.DATABASE_URL_TEST!);
    url.searchParams.set('options', '-c search_path=' + schema);
    db = createPool(url.toString());
    await runMigrations(db, 'migrations');
    const key = await loadSigningKey({ autogenerate: true });
    tokens = new TokenService(key, [key], clock, { issuer: 'https://auth.test', accessTtlSeconds: 900, idTtlSeconds: 900 });
  }, 30000);
  afterAll(async () => {
    await db?.close();
    if (admin) {
      await admin.query(`drop schema if exists ${schema} cascade`);
      await admin.close();
    }
  }, 30000);

  it('two independent services racing on the same head recover one committed successor', async () => {
    const initial = await create().start(start());
    let reads = 0;
    let release!: () => void;
    const barrier = new Promise<void>((resolve) => { release = resolve; });
    const wrapped = (): RefreshTokenStore => {
      const store = new PgRefreshTokenStore(db);
      return { save: store.save.bind(store), rotate: store.rotate.bind(store), consume: store.consume.bind(store),
        findById: store.findById.bind(store), async findByHash(hash) {
          const record = await store.findByHash(hash);
          if (++reads === 2) release();
          await barrier;
          return record;
        } };
    };
    const [a, b] = await Promise.all([create(wrapped()).refresh(initial.refreshToken, {}), create(wrapped()).refresh(initial.refreshToken, {})]);
    expect(a.refreshToken).toBe(b.refreshToken);
    const records = await db.query('select id from refresh_tokens where session_id=$1', [initial.sessionId]);
    expect(records.rowCount).toBe(2);
  });

  it('failure inserting the successor rolls back consumption in real PostgreSQL', async () => {
    const initial = await create().start(start());
    const brokenDb: Db = {
      query: db.query.bind(db), close: async () => {},
      withTransaction: (fn) => db.withTransaction((tx) => fn({ ...tx, query: async (sql, params) => {
        if (/insert into refresh_tokens/i.test(sql)) throw new Error('injected successor insert failure');
        return tx.query(sql, params);
      } })),
    };
    await expect(create(new PgRefreshTokenStore(brokenDb)).refresh(initial.refreshToken, {})).rejects.toThrow('injected successor');
    const stored = await new PgRefreshTokenStore(db).findByHash(sha256Hex(initial.refreshToken));
    expect(stored?.consumedAt).toBeNull();
    expect(stored?.replacedById).toBeNull();
    expect((await create().refresh(initial.refreshToken, {})).refreshToken).toBeTruthy();
  });

  it('a repeated request does not invalidate the successful response arriving last', async () => {
    const service = create();
    const initial = await service.start(start());
    const b = await service.refresh(initial.refreshToken, {});
    clock.advance(1);
    const repeated = await create().refresh(initial.refreshToken, {});
    expect(repeated.refreshToken).toBe(b.refreshToken);
    clock.advance(13 * 60);
    expect((await create().refresh(b.refreshToken, {})).refreshToken).toBeTruthy();
    const session = await new PgSessionStore(db).findById(initial.sessionId);
    expect(session?.revokedAt).toBeNull();
  });

  it('bootstrap is atomic across workers and deleted apps stay deleted after restart', async () => {
    const client = { id: 'seed-once', type: 'internal' as const, redirectUris: ['https://app.example.com/api/auth/callback'], allowedProviders: ['email'] };
    const first = new PgClientRegistry(db);
    const second = new PgClientRegistry(db);
    await Promise.all([first.seedInitial([client]), second.seedInitial([client])]);
    expect(await first.findClient(client.id)).toEqual(client);
    await first.delete(client.id);
    await new PgClientRegistry(db).seedInitial([client]);
    expect(await first.findClient(client.id)).toBeNull();
  });

  it('concurrent first login through different providers links one verified owner', async () => {
    const suffix = randomUUID();
    const email = suffix + '@gmail.com';
    const pid = (provider: string) => ({ provider, subject: provider + suffix, email,
      emailVerified: true, emailAuthoritative: true, profile: { name: 'Concurrency Test' } });
    const services = [new IdentityService(new PgIdentityRepository(db)), new IdentityService(new PgIdentityRepository(db))];
    const results = await Promise.all([services[0]!.resolveLogin(pid('email-code')), services[1]!.resolveLogin(pid('google'))]);
    expect(results[0]!.user.id).toBe(results[1]!.user.id);
    const rows = await db.query('select distinct user_id from identities where subject=$1 or subject=$2', ['email-code' + suffix, 'google' + suffix]);
    expect(rows.rowCount).toBe(1);
    expect((await services[1]!.resolveLogin(pid('google'))).user.id).toBe(results[0]!.user.id);
  });
});
