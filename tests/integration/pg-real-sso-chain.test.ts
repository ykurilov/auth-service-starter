import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { copyFileSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { beforeAll, afterAll, describe, it, expect } from 'vitest';
import { createPool, type Db } from '../../src/adapters/db/pool.js';
import { runMigrations } from '../../src/adapters/db/migrate.js';
import { PgSessionStore } from '../../src/adapters/repository/pg/pg-session-store.js';
import { pgSsoStores } from '../../src/adapters/repository/pg/pg-sso-session-store.js';
import { SsoSessionService } from '../../src/domain/sso/sso-session-service.js';
import type { Session } from '../../src/domain/sessions/session.js';
import { systemClock } from '../../src/ports/clock.js';

// T04 и T12 на НАСТОЯЩЕМ PostgreSQL: выход атомарен (сбой посередине ничего
// не меняет), смена аккаунта гасит сессии цепочки браузера, миграция 0013
// поверх данных прежней версии.
const URL_ENV = process.env.DATABASE_URL_TEST;
const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../migrations');

function withSearchPath(url: string, schema: string): string {
  const u = new URL(url);
  u.searchParams.set('options', `-c search_path=${schema}`);
  return u.toString();
}

// Db, который один раз роняет запрос, подходящий под fail (после arm()).
function failingOnce(inner: Db, fail: RegExp): { db: Db; arm: () => void } {
  const wrap = (d: Db, state: { armed: boolean }): Db => ({
    async query<T>(sql: string, params?: unknown[]) {
      if (state.armed && fail.test(sql)) { state.armed = false; throw new Error('db down'); }
      return d.query<T>(sql, params);
    },
    withTransaction: (fn) => d.withTransaction((tx) => fn(wrap(tx, state))),
    withConnection: (fn, options) => d.withConnection((conn) => fn(wrap(conn, state)), options),
    close: () => d.close(),
  });
  const state = { armed: false };
  return { db: wrap(inner, state), arm: () => { state.armed = true; } };
}

describe.skipIf(!URL_ENV)('Postgres: цепочка SSO-сессий браузера', () => {
  const schema = `sso_${randomUUID().replaceAll('-', '').slice(0, 12)}`;
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
  async function appSession(userId: string, ssoChainId?: string): Promise<Session> {
    const now = new Date();
    const s: Session = { id: randomUUID(), userId, clientId: 'app', provider: 'email', profile: {}, scope: 'openid',
      deviceFingerprint: 'fp', ipHash: 'ip', createdAt: now, lastUsedAt: now,
      expiresAt: new Date(now.getTime() + 3600_000), revokedAt: null, ...(ssoChainId ? { ssoChainId } : {}) };
    await sessions().save(s);
    return s;
  }
  const revoked = async (s: Session) => (await sessions().findById(s.id))?.revokedAt !== null;

  it('T04: сбой отзыва сессий при выходе откатывает и отзыв SSO; повторный выход доводит до конца', async () => {
    const flaky = failingOnce(db, /^update sessions set revoked_at/);
    const sso = new SsoSessionService(pgSsoStores(flaky.db), systemClock, { ssoTtlSeconds: 3600 });
    const alice = randomUUID();
    const { session, rawToken } = await sso.start(alice, { provider: 'email', loginId: randomUUID() });
    const inChain = await appSession(alice, session.chainId);
    const elsewhere = await appSession(alice);

    flaky.arm();
    await expect(sso.signOut(rawToken)).rejects.toThrow('db down');
    expect(await sso.resolve(rawToken)).not.toBeNull();
    expect(await revoked(inChain)).toBe(false);

    await sso.signOut(rawToken);
    expect(await sso.resolve(rawToken)).toBeNull();
    expect(await revoked(inChain)).toBe(true);
    // Выход только в этом браузере: сессия того же пользователя без цепочки остаётся.
    expect(await revoked(elsewhere)).toBe(false);
    // Ещё один повтор по уже отозванной cookie — без ошибок.
    await sso.signOut(rawToken);
  });

  it('T12: смена пользователя гасит сессии цепочки и отзывает прежнюю SSO-сессию; другие цепочки живы', async () => {
    const sso = new SsoSessionService(pgSsoStores(db), systemClock, { ssoTtlSeconds: 3600 });
    const alice = randomUUID();
    const bob = randomUUID();
    const first = await sso.start(alice, { provider: 'email', loginId: randomUUID() });
    const aliceHere = await appSession(alice, first.session.chainId);
    const otherDevice = await sso.start(alice, { provider: 'email', loginId: randomUUID() });
    const aliceThere = await appSession(alice, otherDevice.session.chainId);

    const same = await sso.start(alice, { provider: 'email', loginId: randomUUID() }, first.rawToken);
    expect(same.session.chainId).toBe(first.session.chainId);
    expect(await revoked(aliceHere)).toBe(false);

    // Другой пользователь — новая цепочка, прежняя закрыта.
    const switched = await sso.start(bob, { provider: 'email', loginId: randomUUID() }, same.rawToken);
    expect(switched.session.chainId).not.toBe(first.session.chainId);
    expect(await revoked(aliceHere)).toBe(true);
    expect(await revoked(aliceThere)).toBe(false);
    expect(await sso.resolve(same.rawToken)).toBeNull();
    expect(await sso.resolve(switched.rawToken)).not.toBeNull();
    const store = pgSsoStores(db).sso;
    expect(await store.holdSignedIn(first.session.chainId, alice)).toBe(false);
    expect(await store.holdSignedIn(first.session.chainId, bob)).toBe(false);
    expect(await store.holdSignedIn(switched.session.chainId, bob)).toBe(true);
  });
});

describe.skipIf(!URL_ENV)('Postgres: миграция 0013 поверх данных прежней версии', () => {
  const schema = `mig13_${randomUUID().replaceAll('-', '').slice(0, 12)}`;
  let admin: Db;
  let db: Db;
  let oldDir: string;

  beforeAll(async () => {
    admin = createPool(URL_ENV!);
    await admin.query(`create schema ${schema}`);
    db = createPool(withSearchPath(URL_ENV!, schema));
    oldDir = mkdtempSync(path.join(tmpdir(), 'mig-0012-'));
    for (const f of readdirSync(migrationsDir).filter((n) => /^\d+_.*\.sql$/.test(n) && n < '0013')) {
      copyFileSync(path.join(migrationsDir, f), path.join(oldDir, f));
    }
  }, 30000);

  afterAll(async () => {
    await db?.close();
    await admin?.query(`drop schema if exists ${schema} cascade`);
    await admin?.close();
    rmSync(oldDir, { recursive: true, force: true });
  }, 30000);

  it('старые SSO-сессии получают каждая свою цепочку, старые сессии приложений — без цепочки', async () => {
    await runMigrations(db, oldDir);
    const now = new Date();
    const later = new Date(now.getTime() + 3600_000);
    const user = randomUUID();
    await db.query('insert into users (id, display_name, status, created_at) values ($1, null, $2, $3)', [user, 'active', now]);
    for (const id of [randomUUID(), randomUUID()]) {
      await db.query(`insert into sso_sessions (id, user_id, auth, token_hash, created_at, last_used_at, expires_at, revoked_at)
        values ($1, $2, $3, $4, $5, $5, $6, null)`, [id, user, JSON.stringify({ provider: 'email' }), `h-${id}`, now, later]);
    }
    const sessionId = randomUUID();
    await db.query(`insert into sessions (id, user_id, client_id, provider, profile, scope, device_fingerprint, ip_hash,
        created_at, last_used_at, expires_at, revoked_at) values ($1, $2, 'app', 'email', '{}', 'openid', 'fp', 'ip', $3, $3, $4, null)`,
      [sessionId, user, now, later]);

    expect(await runMigrations(db, migrationsDir)).toBeGreaterThan(0);
    const chains = (await db.query<{ chain_id: string; login_id: string | null }>(
      'select chain_id, login_id from sso_sessions')).rows;
    expect(chains).toHaveLength(2);
    expect(new Set(chains.map((c) => c.chain_id)).size).toBe(2);
    expect(chains.every((c) => c.login_id === null)).toBe(true);
    expect((await new PgSessionStore(db).findById(sessionId))).not.toHaveProperty('ssoChainId');
    expect(await runMigrations(db, migrationsDir)).toBe(0);
  });
});
