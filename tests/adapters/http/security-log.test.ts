import { describe, it, expect, beforeEach } from 'vitest';
import pino from 'pino';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, authorizeForm, loginWithCode, startCodeLogin, TEST_VERIFIER, FORM_HEADERS } from './helpers.js';
import { SessionService } from '../../../src/domain/sessions/session-service.js';
import { InMemorySessionStore } from '../../../src/adapters/repository/in-memory-session-store.js';
import { InMemoryRefreshTokenStore } from '../../../src/adapters/repository/in-memory-refresh-token-store.js';
import { InMemoryClientLock } from '../../../src/adapters/repository/in-memory-client-lock.js';
import { advanceableClock } from '../../helpers/advanceable-clock.js';
import { sha256Hex } from '../../../src/domain/shared/hash.js';

// Собираем warn-записи логгера в массив вместо вывода, чтобы проверять их
// структуру напрямую. pino пишет NDJSON в поток — парсим построчно.
function capturingLogger(): { logger: pino.Logger; records: () => Record<string, unknown>[] } {
  const lines: string[] = [];
  const stream = {
    write(chunk: string) {
      lines.push(chunk);
    },
  };
  const logger = pino({ level: 'warn' }, stream as unknown as NodeJS.WritableStream);
  return {
    logger,
    records: () => lines.filter((l) => l.trim().length > 0).map((l) => JSON.parse(l)),
  };
}

function tokenForm(fields: Record<string, string>): string {
  return new URLSearchParams(fields).toString();
}

describe('журнал событий безопасности', () => {
  let capture: ReturnType<typeof capturingLogger>;

  beforeEach(() => {
    capture = capturingLogger();
  });

  it('переиспользование refresh-токена после ротации → warn refresh_token_reuse', async () => {
    const deps = await makeTestDeps();
    deps.logger = capture.logger;
    const clock = advanceableClock(new Date('2026-07-02T00:00:00Z'));
    const refreshStore = new InMemoryRefreshTokenStore();
    deps.sessions = new SessionService(new InMemorySessionStore(refreshStore), refreshStore,
      deps.tokens, clock, { refreshTtlSeconds: deps.config.refreshTtlSeconds });
    // Обмен кода создаёт сессию через блокировку клиента — с тем же сервисом сессий.
    deps.clientLock = new InMemoryClientLock(deps.adminClients!, { codes: deps.codes, sessions: deps.sessions },
      async () => {});
    const app = buildServer(deps);
    const code = await loginWithCode(app);

    const first = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.example/cb',
        client_id: 'app',
        code_verifier: TEST_VERIFIER,
      }),
      headers: FORM_HEADERS,
    });
    const initial = first.json();

    // Real reuse is presenting a consumed token after grace, rather than
    // merely a deep but fresh chain of otherwise legitimate refreshes.
    const rotated = await app.inject({ method: 'POST', url: '/oauth/token',
      payload: tokenForm({ grant_type: 'refresh_token', refresh_token: initial.refresh_token }),
      headers: FORM_HEADERS });
    expect(rotated.statusCode).toBe(200);
    clock.advance(61);

    const reused = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: tokenForm({
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token,
      }),
      headers: FORM_HEADERS,
    });
    expect(reused.statusCode).toBe(400);
    expect(reused.json().error).toBe('invalid_grant');

    const records = capture.records();
    const reuseRecord = records.find((r) => r.event === 'refresh_token_reuse');
    expect(reuseRecord).toBeDefined();
    expect(reuseRecord?.msg).toBe('событие безопасности');
    expect(typeof reuseRecord?.ipHash).toBe('string');
    expect(reuseRecord?.email).toBeUndefined();
    expect(reuseRecord?.refresh_token).toBeUndefined();
    await app.close();
  });

  it('неверный код на /authorize/code/verify → warn login_failed method=email_code', async () => {
    const deps = await makeTestDeps({ fixedCode: 'CODE55' });
    deps.logger = capture.logger;
    const app = buildServer(deps);

    const challenge = await startCodeLogin(app, 'user@y.com');

    const res = await app.inject({
      method: 'POST',
      url: '/authorize/code/verify',
      payload: authorizeForm({ challenge, code: 'WRONGCODE' }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(200);

    const records = capture.records();
    const record = records.find((r) => r.event === 'login_failed');
    expect(record).toBeDefined();
    expect(record?.method).toBe('email_code');
    expect(record?.emailHash).toBe(sha256Hex('user@y.com'));
    expect(typeof record?.ipHash).toBe('string');
    expect(record?.email).toBeUndefined();
    expect(record?.code).toBeUndefined();
    await app.close();
  });

  it('сбой инфраструктуры при входе по коду → 500 без login_failed в логе', async () => {
    const deps = await makeTestDeps({ fixedCode: 'CODE55' });
    deps.logger = capture.logger;
    deps.sso.start = async () => {
      throw new Error('db down');
    };
    const app = buildServer(deps);

    const challenge = await startCodeLogin(app, 'user@y.com');

    const res = await app.inject({
      method: 'POST',
      url: '/authorize/code/verify',
      payload: authorizeForm({ challenge, code: 'CODE55' }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(500);
    expect(res.body).not.toContain('Неверный или просроченный код');

    const records = capture.records();
    expect(records.find((r) => r.event === 'login_failed')).toBeUndefined();
    await app.close();
  });
});
