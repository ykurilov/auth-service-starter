import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import type { LightMyRequestResponse } from 'fastify';
import { createPool, type Db } from '../../src/adapters/db/pool.js';
import { runMigrations } from '../../src/adapters/db/migrate.js';
import { PgClientRegistry } from '../../src/adapters/repository/pg/pg-client-registry.js';
import { PgAuthorizationCodeStore } from '../../src/adapters/repository/pg/pg-authorization-code-store.js';
import { PgSessionStore } from '../../src/adapters/repository/pg/pg-session-store.js';
import { PgRefreshTokenStore } from '../../src/adapters/repository/pg/pg-refresh-token-store.js';
import { PgSsoSessionStore, pgSsoStores } from '../../src/adapters/repository/pg/pg-sso-session-store.js';
import { PgClientLock } from '../../src/adapters/repository/pg/pg-client-lock.js';
import { AuthorizationCodeService } from '../../src/domain/login/authorization-code-service.js';
import { SessionService } from '../../src/domain/sessions/session-service.js';
import { LoginService } from '../../src/domain/login/login-service.js';
import { IdentityService } from '../../src/domain/identity/identity-service.js';
import { SsoSessionService } from '../../src/domain/sso/sso-session-service.js';
import type { Client } from '../../src/domain/clients/client.js';
import { systemClock } from '../../src/ports/clock.js';
import { buildServer } from '../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CHALLENGE, TEST_VERIFIER, TEST_CSRF, extractChallenge } from '../adapters/http/helpers.js';

// A4, A5 через HTTP на НАСТОЯЩЕМ PostgreSQL: тихий вход по SSO-сессии,
// начатой до миграции 0013 (без loginId), и задержанный повторный вход с
// прежней cookie после смены аккаунта.
const URL_ENV = process.env.DATABASE_URL_TEST;
const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../migrations');

const client: Client = { id: 'app', type: 'internal', redirectUris: ['https://app.example/cb'], allowedProviders: ['email'] };
const client2: Client = { ...client, id: 'app2', redirectUris: ['https://app2.example/cb'] };
const oidc = (c: Client) => ({ client_id: c.id, redirect_uri: c.redirectUris[0]!, code_challenge: TEST_CHALLENGE,
  code_challenge_method: 'S256', scope: 'openid email' });
const headers = (sso?: string) => ({ 'content-type': 'application/x-www-form-urlencoded',
  cookie: `csrf=${TEST_CSRF}${sso ? `; sso=${sso}` : ''}` });
const form = (extra: Record<string, string>) => new URLSearchParams({ ...oidc(client), csrf: TEST_CSRF, ...extra }).toString();
const ssoCookie = (r: LightMyRequestResponse) => r.cookies.find((c) => c.name === 'sso')?.value;
const codeOf = (r: LightMyRequestResponse) => new URL(String(r.headers.location)).searchParams.get('code')!;

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

async function setup() {
  const deps = await makeTestDeps({ clients: [client] });
  const admin = createPool(URL_ENV!);
  const schema = `ssoh_${randomUUID().replaceAll('-', '').slice(0, 12)}`;
  await admin.query(`create schema ${schema}`);
  const u = new URL(URL_ENV!);
  u.searchParams.set('options', `-c search_path=${schema}`);
  const db = createPool(u.toString());
  await runMigrations(db, migrationsDir);
  const registry = new PgClientRegistry(db);
  await registry.create(client);
  await registry.create(client2);
  const services = (d: Db) => ({
    codes: new AuthorizationCodeService(new PgAuthorizationCodeStore(d), systemClock, 60),
    sessions: new SessionService(new PgSessionStore(d), new PgRefreshTokenStore(d), deps.tokens, systemClock,
      { refreshTtlSeconds: 2592000 }),
    sso: new PgSsoSessionStore(d),
  });
  const svc = services(db);
  const stores = pgSsoStores(db);
  Object.assign(deps, {
    clients: registry, adminClients: registry, codes: svc.codes, sessions: svc.sessions, ssoStores: stores,
    login: new LoginService(registry, new IdentityService(deps.repo), svc.codes),
    clientLock: new PgClientLock(db, services),
    sso: new SsoSessionService(stores, systemClock, { ssoTtlSeconds: 3600 }),
  });
  const app = buildServer(deps);
  app.addHook('onClose', async () => {
    await db.close();
    await admin.query(`drop schema ${schema} cascade`);
    await admin.close();
  });
  const exchange = (code: string, c: Client = client) => app.inject({ method: 'POST', url: '/oauth/token', payload: {
    grant_type: 'authorization_code', code, client_id: c.id, redirect_uri: c.redirectUris[0]!, code_verifier: TEST_VERIFIER } });
  const verify = (challenge: string, sso?: string) => app.inject({ method: 'POST', url: '/authorize/code/verify',
    headers: headers(sso), payload: form({ challenge, code: 'CODE55' }) });
  async function identify(email: string, sso?: string) {
    const r = await app.inject({ method: 'POST', url: '/authorize/identify', headers: headers(sso), payload: form({ email }) });
    expect(r.statusCode).toBe(200);
    return extractChallenge(r.body);
  }
  async function login(email: string, sso?: string) {
    const r = await verify(await identify(email, sso), sso);
    expect(r.statusCode).toBe(302);
    const t = await exchange(codeOf(r));
    expect(t.statusCode).toBe(200);
    return { sso: ssoCookie(r)!, refresh: t.json().refresh_token as string };
  }
  const refresh = (token: string) => app.inject({ method: 'POST', url: '/oauth/token',
    payload: { grant_type: 'refresh_token', refresh_token: token } });
  const silent = (sso: string, c: Client = client) => app.inject({ method: 'GET',
    url: `/authorize?${new URLSearchParams({ ...oidc(c), prompt: 'none' })}`, headers: headers(sso) });
  return { deps, app, db, identify, verify, exchange, login, refresh, silent };
}

describe.skipIf(!URL_ENV)('Postgres + HTTP: смена аккаунта в браузере', () => {
  it('A4: код тихого входа по SSO-сессии без loginId (до миграции 0013) не обменивается после смены аккаунта', async () => {
    const s = await setup();
    try {
      const alice = await s.login('alice@x.com');
      // Форма SSO-сессии прежней версии: в auth нет loginId, login_id пуст.
      const old = (await s.deps.sso.resolve(alice.sso))!;
      delete old.auth.loginId;
      await s.db.query('update sso_sessions set auth = $2, login_id = null where id = $1', [old.id, JSON.stringify(old.auth)]);
      const pending = await s.silent(alice.sso);
      expect(pending.statusCode).toBe(302);
      const code = codeOf(pending);

      await s.login('bob@x.com', alice.sso);

      const exchanged = await s.exchange(code);
      expect(exchanged.statusCode).toBe(400);
      expect(exchanged.json().error).toBe('invalid_grant');
    } finally { await s.app.close(); }
  });

  it('A4: сессия приложения по коду тихого входа через SSO-сессию без loginId гаснет при смене аккаунта', async () => {
    const s = await setup();
    try {
      const alice = await s.login('alice@x.com');
      const old = (await s.deps.sso.resolve(alice.sso))!;
      delete old.auth.loginId;
      await s.db.query('update sso_sessions set auth = $2, login_id = null where id = $1', [old.id, JSON.stringify(old.auth)]);
      const exchanged = await s.exchange(codeOf(await s.silent(alice.sso)));
      expect(exchanged.statusCode).toBe(200);
      // Сессия приложения привязана к цепочке браузера: смена аккаунта её гасит.
      await s.login('bob@x.com', alice.sso);
      expect((await s.refresh(exchanged.json().refresh_token)).statusCode).toBe(400);
    } finally { await s.app.close(); }
  });

  // С круга 10 прежняя cookie ведёт только в прежнюю цепочку: сервер не
  // отличит задержанный запрос этого браузера от копии cookie у прежнего
  // владельца цепочки, а тот не должен разлогинивать вошедшего. Цена: если
  // вход Alice, отправленный до входа Bob, придёт после него, сессии Bob,
  // выданные в эти секунды, этот браузер уже не погасит — они истекут сами.
  it('A5: задержанный повторный вход Alice с прежней cookie после входа Bob продолжает её цепочку и не трогает Bob', async () => {
    const s = await setup();
    try {
      const alice = await s.login('alice@x.com');
      const challenge = await s.identify('alice@x.com', alice.sso);
      const entered = deferred();
      const released = deferred();
      const original = s.deps.sso.start.bind(s.deps.sso);
      let pause = true;
      s.deps.sso.start = async (...args) => {
        if (pause) { pause = false; entered.resolve(); await released.promise; }
        return original(...args);
      };
      const inFlight = s.verify(challenge, alice.sso);
      await entered.promise;

      const bob = await s.login('bob@x.com', alice.sso);
      const bobApp2 = await s.exchange(codeOf(await s.silent(bob.sso, client2)), client2);
      expect(bobApp2.statusCode).toBe(200);

      released.resolve();
      const aliceAgain = await inFlight;
      expect(aliceAgain.statusCode).toBe(302);
      expect((await s.exchange(codeOf(aliceAgain))).statusCode).toBe(200);
      expect((await s.deps.sso.resolve(ssoCookie(aliceAgain)!))?.auth.email).toBe('alice@x.com');
      expect((await s.refresh(bobApp2.json().refresh_token)).statusCode).toBe(200);
      expect((await s.refresh(bob.refresh)).statusCode).toBe(200);
    } finally { await s.app.close(); }
  });
});
