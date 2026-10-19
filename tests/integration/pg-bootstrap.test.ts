import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { bootstrap } from '../../src/index.js';
import { createMemDb } from '../helpers/pg-mem-db.js';
import { TEST_VERIFIER, TEST_CHALLENGE, TEST_CSRF, FORM_HEADERS, extractChallenge, confirmConsent } from '../adapters/http/helpers.js';
import type { Db } from '../../src/adapters/db/pool.js';

const FORM = FORM_HEADERS;

const CLIENT = {
  id: 'shop',
  type: 'external',
  redirectUris: ['https://shop.example/cb'],
  allowedProviders: ['email'],
};

function oidc(extra: Record<string, string> = {}): Record<string, string> {
  return {
    client_id: 'shop',
    redirect_uri: 'https://shop.example/cb',
    code_challenge: TEST_CHALLENGE,
    code_challenge_method: 'S256',
    scope: 'openid',
    state: 'st1',
    ...extra,
  };
}

// Сквозной поток на РЕАЛЬНОМ хранилище (pg-mem через Db-адаптер): регистрация,
// выдача кода, обмен на токены, refresh. Один экземпляр Db на весь bootstrap —
// иначе состояние pg-mem потерялось бы между обращениями.
describe('bootstrap на Postgres-хранилище (pg-mem)', () => {
  let app: FastifyInstance;
  let db: Db;

  beforeAll(async () => {
    db = createMemDb();
    const booted = await bootstrap(
      {
        PUBLIC_ISSUER_URL: 'https://auth.example',
        KEY_AUTOGENERATE: 'true',
        LOG_LEVEL: 'silent',
        DATABASE_URL: 'postgres://mem',
        SSO_COOKIE_SECURE: 'false',
        CLIENTS_JSON: JSON.stringify([CLIENT]),
      } as NodeJS.ProcessEnv,
      { dbFactory: () => db, codeGenerator: () => 'CODE55' },
    );
    app = booted.app;
  });

  afterAll(async () => {
    await app.close();
    await db.close();
  });

  it('вход по коду → token → refresh через Postgres-слой', async () => {
    // 1. GET /authorize → форма входа (клиент засижен в БД через upsert).
    const authRes = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams(oidc()).toString()}`,
    });
    expect(authRes.statusCode).toBe(200);
    expect(authRes.body).toContain('/authorize/identify');

    // 2. identify (код записан в email_secrets Postgres-слоя) → code/verify →
    // экран согласия внешнего приложения → «Продолжить» → 302 с code= в
    // Location (пользователь, authorization-код и sso-сессия — в БД).
    const identify = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: new URLSearchParams({ ...oidc(), email: 'pg-user@example.com', csrf: TEST_CSRF }).toString(),
      headers: FORM,
    });
    const challenge = extractChallenge(identify.body);
    const verifyRes = await app.inject({
      method: 'POST',
      url: '/authorize/code/verify',
      payload: new URLSearchParams({
        ...oidc(),
        challenge,
        code: 'CODE55',
        csrf: TEST_CSRF,
      }).toString(),
      headers: FORM,
    });
    expect(verifyRes.statusCode).toBe(303);
    const location = new URL(await confirmConsent(app, verifyRes, verifyRes.headers['location'] as string));
    expect(location.origin + location.pathname).toBe('https://shop.example/cb');
    const code = location.searchParams.get('code');
    expect(code).toBeTruthy();
    const setCookie = verifyRes.headers['set-cookie'];
    const ssoLine = (Array.isArray(setCookie) ? setCookie : [String(setCookie ?? '')]).find((l) =>
      l.startsWith('sso='),
    );
    expect(ssoLine).toBeTruthy();

    // 3. POST /oauth/token (authorization_code) → 200 с токенами. Тот же verifier,
    // что даёт TEST_CHALLENGE (пара из helpers).
    const tokenRes = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code!,
        redirect_uri: 'https://shop.example/cb',
        client_id: 'shop',
        code_verifier: TEST_VERIFIER,
      }).toString(),
      headers: FORM,
    });
    expect(tokenRes.statusCode).toBe(200);
    const tokens = tokenRes.json();
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();

    // 4. refresh: grant_type=refresh_token → 200 (refresh-токен прочитан из БД).
    const refreshRes = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token,
      }).toString(),
      headers: FORM,
    });
    expect(refreshRes.statusCode).toBe(200);
    const refreshed = refreshRes.json();
    expect(refreshed.access_token).toBeTruthy();
    expect(refreshed.refresh_token).toBeTruthy();
  });
});

// T29: выключение дожидается идущей очистки и только потом закрывает базу.
describe('bootstrap: фоновая очистка при выключении', () => {
  it('shutdownGracefully ждёт прогон очистки, затем закрывает db; новых прогонов нет', async () => {
    const { shutdownGracefully } = await import('../../src/index.js');
    const inner = createMemDb();
    const events: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let cleanupStarted!: () => void;
    const started = new Promise<void>((r) => { cleanupStarted = r; });
    let closed = false;
    const db: Db = {
      async query(sql, params) {
        if (closed) events.push(`запрос после закрытия: ${sql.slice(0, 30)}`);
        if (/^delete from authorization_codes/.test(sql)) { cleanupStarted(); await gate; }
        return inner.query(sql, params);
      },
      withTransaction: (fn) => inner.withTransaction(fn),
      withConnection: (fn) => inner.withConnection(fn),
      async close() { closed = true; events.push('db закрыта'); await inner.close(); },
    };
    const booted = await bootstrap(
      { PUBLIC_ISSUER_URL: 'https://auth.example', KEY_AUTOGENERATE: 'true', LOG_LEVEL: 'silent',
        DATABASE_URL: 'postgres://mem', CLIENTS_JSON: JSON.stringify([CLIENT]) } as NodeJS.ProcessEnv,
      { dbFactory: () => db },
    );
    await started;
    const stopping = shutdownGracefully(booted.app, booted.db, booted.rateLimiter);
    await new Promise((r) => setImmediate(r));
    expect(events).toEqual([]);
    release();
    await stopping;
    expect(events).toEqual(['db закрыта']);
  });
});
