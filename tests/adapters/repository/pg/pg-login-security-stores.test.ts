import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMemDb } from '../../../helpers/pg-mem-db.js';
import { advanceableClock, type AdvanceableClock } from '../../../helpers/advanceable-clock.js';
import { runMigrations } from '../../../../src/adapters/db/migrate.js';
import type { Db } from '../../../../src/adapters/db/pool.js';
import { PgLoginChallengeStore } from '../../../../src/adapters/repository/pg/pg-login-challenge-store.js';
import { PgGoogleNonceStore } from '../../../../src/adapters/repository/pg/pg-google-nonce-store.js';
import { PgRateLimiter } from '../../../../src/adapters/ratelimit/pg-rate-limiter.js';
import { PgIdentityRepository } from '../../../../src/adapters/repository/pg/pg-identity-repository.js';
import { EmailCodeProvider } from '../../../../src/domain/email-login/email-code-provider.js';
import { GoogleNonceService } from '../../../../src/domain/google-login/google-nonce.js';
import { IdentityService, EmailOwnershipRequiredError } from '../../../../src/domain/identity/identity-service.js';
import { InvalidCredentialsError } from '../../../../src/domain/email-login/errors.js';
import { FakeMailer } from '../../../../src/adapters/mail/fake-mailer.js';

// Клиент, под которым начинается и проверяется попытка входа.
const TEST_CLIENT = { id: 'app', registrationId: '00000000-0000-4000-8000-000000000001' };

// Контракт Postgres-адаптеров попыток входа, nonce Google и лимитера на pg-mem.
// «Несколько экземпляров» и «перезапуск» = независимые объекты сервисов поверх
// одной БД: всё состояние в таблицах, ничего не держится в памяти процесса.
// pg-mem не моделирует блокировки строк и не откатывает ROLLBACK — конкуренцию
// и откат проверяет tests/integration/pg-real-security.test.ts на Postgres.

const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../migrations');

let db: Db;
let clock: AdvanceableClock;

beforeEach(async () => {
  db = createMemDb();
  await runMigrations(db, migrationsDir);
  clock = advanceableClock(new Date('2026-07-01T00:00:00Z'));
});
afterEach(async () => {
  await db.close();
});

function codeInstance(mailer = new FakeMailer(), code = '424242') {
  return {
    mailer,
    provider: new EmailCodeProvider(new PgLoginChallengeStore(db), mailer, clock, {
      appName: 'Auth Service',
      codeTtlMinutes: 15,
      generateCode: () => code,
    }),
  };
}

describe('PgLoginChallengeStore через EmailCodeProvider', () => {
  it('попытка, начатая одним экземпляром, проверяется другим (и после перезапуска)', async () => {
    const a = codeInstance();
    const { handle } = await a.provider.start({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT });
    const restarted = codeInstance();
    const pid = await restarted.provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '424242' });
    expect(pid.email).toBe('u@x.com');
    // Погашена для всех экземпляров.
    await expect(a.provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '424242' })).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
  });

  it('лимит проверок общий для экземпляров: 5 неверных через разные экземпляры', async () => {
    const { handle } = await codeInstance().provider.start({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT });
    for (let i = 0; i < 5; i++) {
      await expect(codeInstance().provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: `0${i}` })).rejects.toBeInstanceOf(
        InvalidCredentialsError,
      );
    }
    await expect(codeInstance().provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '424242' })).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
    const { rows } = await db.query<{ attempts: number }>('select attempts from email_login_challenges');
    expect(Number(rows[0]!.attempts)).toBe(5);
  });

  it('в БД нет ни handle, ни кода в открытом виде; код солён handle', async () => {
    const { handle } = await codeInstance().provider.start({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT });
    const { rows } = await db.query<Record<string, unknown>>('select * from email_login_challenges');
    const dump = JSON.stringify(rows);
    expect(dump).not.toContain(handle);
    expect(dump).not.toContain('424242');
    expect(dump).not.toContain('"b"');
  });

  it('переотправка заменяет код атомарно; лимит переотправок в БД', async () => {
    const codes = ['111111', '222222', '333333', '444444', '555555'];
    const provider = new EmailCodeProvider(new PgLoginChallengeStore(db), new FakeMailer(), clock, {
      appName: 'G',
      codeTtlMinutes: 15,
      generateCode: () => codes.shift()!,
    });
    const { handle } = await provider.start({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT });
    expect(await provider.resend({ handle, binding: 'b', client: TEST_CLIENT })).toEqual({ email: 'u@x.com' });
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '111111' })).rejects.toBeInstanceOf(InvalidCredentialsError);
    await provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    await provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    expect(await provider.resend({ handle, binding: 'b', client: TEST_CLIENT })).toBeNull();
    expect((await provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '444444' })).email).toBe('u@x.com');
  });

  it('отложенная привязка сохраняется и возвращается', async () => {
    const { provider } = codeInstance();
    const link = { provider: 'google', subject: 'g-1', name: 'G' };
    const { handle } = await provider.start({ email: 'u@corp.example', binding: 'b', client: TEST_CLIENT, link });
    expect((await codeInstance().provider.verifyChallenge({ handle, binding: 'b', client: TEST_CLIENT, code: '424242' })).link).toEqual(link);
  });

  it('deleteExpired удаляет истёкшие попытки', async () => {
    await codeInstance().provider.start({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT });
    expect(await new PgLoginChallengeStore(db).deleteExpired(new Date(clock.now().getTime() + 16 * 60_000))).toBe(1);
  });
});

describe('PgGoogleNonceStore', () => {
  it('nonce, выпущенный одним экземпляром, гасится другим ровно один раз', async () => {
    const nonce = await new GoogleNonceService(new PgGoogleNonceStore(db), clock).issue('b', 'app');
    const other = new GoogleNonceService(new PgGoogleNonceStore(db), clock);
    expect(await other.consume(nonce, 'other-browser', 'app')).toBe(false);
    expect(await other.consume(nonce, 'b', 'app2')).toBe(false);
    expect(await other.consume(nonce, 'b', 'app')).toBe(true);
    expect(await new GoogleNonceService(new PgGoogleNonceStore(db), clock).consume(nonce, 'b', 'app')).toBe(false);
  });

  it('просроченный nonce не гасится', async () => {
    const svc = new GoogleNonceService(new PgGoogleNonceStore(db), clock, 60);
    const nonce = await svc.issue('b', 'app');
    clock.advance(61);
    expect(await svc.consume(nonce, 'b', 'app')).toBe(false);
  });
});

describe('PgRateLimiter', () => {
  it('счётчик общий для экземпляров и переживает перезапуск; окно сбрасывается', async () => {
    const results = [];
    for (let i = 0; i < 4; i++) results.push((await new PgRateLimiter(db, clock).hit('k', 3, 60)).allowed);
    expect(results).toEqual([true, true, true, false]);
    const blocked = await new PgRateLimiter(db, clock).hit('k', 3, 60);
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);
    clock.advance(61);
    expect((await new PgRateLimiter(db, clock).hit('k', 3, 60)).allowed).toBe(true);
  });

  it('ключи хранятся хешем', async () => {
    await new PgRateLimiter(db, clock).hit('code-req-email:victim@x.com', 3, 60);
    const { rows } = await db.query('select * from rate_limit_counters');
    expect(JSON.stringify(rows)).not.toContain('victim@x.com');
  });
});

describe('PgIdentityRepository.runAtomic + IdentityService', () => {
  it('первые входы Google и кодом одним адресом (последовательно) → один пользователь', async () => {
    const service = new IdentityService(new PgIdentityRepository(db));
    const a = await service.resolveLogin({ provider: 'google', subject: 'g-1', email: 'a@gmail.com', emailVerified: true, profile: {} });
    const b = await service.resolveLogin({ provider: 'email', subject: 'code:a@gmail.com', email: 'a@gmail.com', emailVerified: true, profile: {} });
    expect(b.user.id).toBe(a.user.id);
    const { rows } = await db.query<{ n: number }>('select count(*)::int as n from users');
    expect(Number(rows[0]!.n)).toBe(1);
  });

  it('сторонний адрес Google без доказанного владения → ничего не записано', async () => {
    const service = new IdentityService(new PgIdentityRepository(db));
    await expect(
      service.resolveLogin({ provider: 'google', subject: 'g-x', email: 'boss@corp.example', emailVerified: false, profile: {} }),
    ).rejects.toBeInstanceOf(EmailOwnershipRequiredError);
    const { rows } = await db.query<{ n: number }>('select count(*)::int as n from users');
    expect(Number(rows[0]!.n)).toBe(0);
  });

  it('advisoryKey детерминирован и укладывается в bigint', () => {
    const k = PgIdentityRepository.advisoryKey('email:a@b.com');
    expect(k).toBe(PgIdentityRepository.advisoryKey('email:a@b.com'));
    const n = BigInt(k);
    expect(n >= -(2n ** 63n) && n < 2n ** 63n).toBe(true);
  });
});
