import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect } from 'vitest';
import type { LightMyRequestResponse } from 'fastify';
import { createPool, type Db } from '../../src/adapters/db/pool.js';
import { runMigrations } from '../../src/adapters/db/migrate.js';
import { PgClientRegistry } from '../../src/adapters/repository/pg/pg-client-registry.js';
import { PgAuthorizationCodeStore } from '../../src/adapters/repository/pg/pg-authorization-code-store.js';
import { PgSessionStore } from '../../src/adapters/repository/pg/pg-session-store.js';
import { PgRefreshTokenStore } from '../../src/adapters/repository/pg/pg-refresh-token-store.js';
import { PgSsoSessionStore, pgSsoStores } from '../../src/adapters/repository/pg/pg-sso-session-store.js';
import { PgIdentityRepository } from '../../src/adapters/repository/pg/pg-identity-repository.js';
import { PgLoginChallengeStore } from '../../src/adapters/repository/pg/pg-login-challenge-store.js';
import { PgRateLimiter } from '../../src/adapters/ratelimit/pg-rate-limiter.js';
import { PgClientLock } from '../../src/adapters/repository/pg/pg-client-lock.js';
import { AuthorizationCodeService } from '../../src/domain/login/authorization-code-service.js';
import { SessionService } from '../../src/domain/sessions/session-service.js';
import { LoginService } from '../../src/domain/login/login-service.js';
import { IdentityService } from '../../src/domain/identity/identity-service.js';
import { SsoSessionService } from '../../src/domain/sso/sso-session-service.js';
import { EmailCodeProvider } from '../../src/domain/email-login/email-code-provider.js';
import type { Client } from '../../src/domain/clients/client.js';
import { buildServer } from '../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CHALLENGE, TEST_VERIFIER, TEST_CSRF, extractChallenge } from '../adapters/http/helpers.js';

// Сервис целиком через HTTP на НАСТОЯЩЕМ PostgreSQL (своя схема на тест) с
// подменёнными часами: сроки cookie и сессий двигаются без ожидания.
// Боевые сроки: SSO-сессия и сессия приложения — по 30 дней.

export const DAY = 86400;
const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../migrations');

// Cookie браузера, которые тест передаёт явно: что браузер выбросил по
// Max-Age, тест просто не отправляет.
export interface BrowserCookies { sso?: string; binding?: string }

export const BINDING_COOKIE = 'sso_browser';

export function cookieHeader(c: BrowserCookies = {}): string {
  return [`csrf=${TEST_CSRF}`, c.sso ? `sso=${c.sso}` : '', c.binding ? `${BINDING_COOKIE}=${c.binding}` : '']
    .filter(Boolean).join('; ');
}

export const setCookie = (r: LightMyRequestResponse, name: string) => r.cookies.find((c) => c.name === name);
export const codeOf = (r: LightMyRequestResponse) => new URL(String(r.headers.location)).searchParams.get('code');

export async function setupPgHttp(clients: Client[]) {
  const deps = await makeTestDeps({ clients });
  const url = process.env.DATABASE_URL_TEST!;
  const admin = createPool(url);
  const schema = `r8_${randomUUID().replaceAll('-', '').slice(0, 12)}`;
  await admin.query(`create schema ${schema}`);
  const u = new URL(url);
  u.searchParams.set('options', `-c search_path=${schema}`);
  const db = createPool(u.toString());
  await runMigrations(db, migrationsDir);
  const registry = new PgClientRegistry(db);
  for (const c of clients) await registry.create(c);
  const clock = deps.clock;
  const services = (d: Db) => ({
    codes: new AuthorizationCodeService(new PgAuthorizationCodeStore(d), clock, 60),
    sessions: new SessionService(new PgSessionStore(d), new PgRefreshTokenStore(d), deps.tokens, clock,
      { refreshTtlSeconds: 30 * DAY }),
    sso: new PgSsoSessionStore(d),
  });
  const svc = services(db);
  const stores = pgSsoStores(db);
  const repo = new PgIdentityRepository(db);
  Object.assign(deps, {
    clients: registry, adminClients: registry, codes: svc.codes, sessions: svc.sessions, identity: repo,
    login: new LoginService(registry, new IdentityService(repo), svc.codes),
    clientLock: new PgClientLock(db, services),
    ssoStores: stores,
    sso: new SsoSessionService(stores, clock, { ssoTtlSeconds: 30 * DAY }),
    codeProvider: new EmailCodeProvider(new PgLoginChallengeStore(db), deps.mailer, clock,
      { appName: 'Test', codeTtlMinutes: 15, generateCode: () => 'CODE55' }),
    otpRateLimiter: new PgRateLimiter(db, clock),
  });
  const app = buildServer(deps);

  const oidc = (c: Client) => ({ client_id: c.id, redirect_uri: c.redirectUris[0]!, code_challenge: TEST_CHALLENGE,
    code_challenge_method: 'S256', scope: 'openid email', state: 'st' });
  const formHeaders = (c: BrowserCookies = {}, extra: Record<string, string> = {}) =>
    ({ 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(c), ...extra });
  const form = (c: Client, extra: Record<string, string>) =>
    new URLSearchParams({ ...oidc(c), csrf: TEST_CSRF, ...extra }).toString();

  // Ввод почты и верного кода. Возвращает ответ проверки кода и cookie,
  // которые браузер получил бы после него (новые поверх прежних).
  async function codeLogin(c: Client, email: string, cookies: BrowserCookies = {}, extraHeaders: Record<string, string> = {}) {
    const start = await app.inject({ method: 'POST', url: '/authorize/identify', headers: formHeaders(cookies),
      payload: form(c, { email }) });
    expect(start.statusCode).toBe(200);
    const verify = await app.inject({ method: 'POST', url: '/authorize/code/verify',
      headers: formHeaders(cookies, extraHeaders), payload: form(c, { challenge: extractChallenge(start.body), code: 'CODE55' }) });
    return { verify, cookies: nextCookies(cookies, verify) };
  }

  const exchange = (code: string, c: Client) => app.inject({ method: 'POST', url: '/oauth/token', payload: {
    grant_type: 'authorization_code', code, client_id: c.id, redirect_uri: c.redirectUris[0]!, code_verifier: TEST_VERIFIER } });
  const refresh = (token: string) => app.inject({ method: 'POST', url: '/oauth/token',
    payload: { grant_type: 'refresh_token', refresh_token: token } });
  const authorize = (c: Client, cookies: BrowserCookies = {}, extra: Record<string, string> = {}) =>
    app.inject({ url: `/authorize?${new URLSearchParams({ ...oidc(c), ...extra })}`, headers: { cookie: cookieHeader(cookies) } });
  const logout = (c: Client, cookies: BrowserCookies) => app.inject({ method: 'POST', url: '/logout',
    headers: formHeaders(cookies), payload: new URLSearchParams({ client_id: c.id, csrf: TEST_CSRF }).toString() });

  // Вход в internal-приложение по коду с обменом на токены.
  async function signIn(c: Client, email: string, cookies: BrowserCookies = {}) {
    const { verify, cookies: next } = await codeLogin(c, email, cookies);
    expect(verify.statusCode).toBe(302);
    const tokens = await exchange(codeOf(verify)!, c);
    expect(tokens.statusCode).toBe(200);
    return { tokens: tokens.json() as { access_token: string; refresh_token: string }, cookies: next };
  }

  const close = async () => {
    await app.close();
    await db.close();
    await admin.query(`drop schema ${schema} cascade`);
    await admin.close();
  };
  return { app, db, clock, oidc, form, formHeaders, codeLogin, exchange, refresh, authorize, logout, signIn, close };
}

// Состояние до миграции 0018: привязок браузеров нет ни в одной таблице.
export async function forgetBindings(db: Db): Promise<void> {
  await db.query('delete from sso_browser_bindings');
  const { rows } = await db.query<{ t: string | null }>("select to_regclass('sso_chain_bindings')::text as t");
  if (rows[0]!.t) await db.query('delete from sso_chain_bindings');
}

// Cookie браузера после ответа: выставленные заменяют прежние, стёртые
// (пустое значение) пропадают.
export function nextCookies(prev: BrowserCookies, r: LightMyRequestResponse): BrowserCookies {
  const next = { ...prev };
  const apply = (name: string, key: keyof BrowserCookies) => {
    const c = setCookie(r, name);
    if (!c) return;
    if (c.value) next[key] = c.value;
    else delete next[key];
  };
  apply('sso', 'sso');
  apply(BINDING_COOKIE, 'binding');
  return next;
}
