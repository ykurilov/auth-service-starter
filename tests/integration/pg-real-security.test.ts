import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { createPool, type Db } from '../../src/adapters/db/pool.js';
import { runMigrations } from '../../src/adapters/db/migrate.js';
import { PgIdentityRepository } from '../../src/adapters/repository/pg/pg-identity-repository.js';
import { PgLoginChallengeStore } from '../../src/adapters/repository/pg/pg-login-challenge-store.js';
import { PgGoogleNonceStore } from '../../src/adapters/repository/pg/pg-google-nonce-store.js';
import { PgRateLimiter } from '../../src/adapters/ratelimit/pg-rate-limiter.js';
import { IdentityService, EmailOwnershipRequiredError } from '../../src/domain/identity/identity-service.js';
import { EmailCodeProvider } from '../../src/domain/email-login/email-code-provider.js';
import { GoogleNonceService } from '../../src/domain/google-login/google-nonce.js';
import { FakeMailer } from '../../src/adapters/mail/fake-mailer.js';
import { MailDeliveryError } from '../../src/ports/mailer.js';
import { systemClock } from '../../src/ports/clock.js';
import type { ProviderIdentity } from '../../src/domain/identity/provider-identity.js';

// Клиент, под которым начинается и проверяется попытка входа.
const TEST_CLIENT = { id: 'app', registrationId: '00000000-0000-4000-8000-000000000001' };

// Конкуренция, блокировки и откат на НАСТОЯЩЕМ PostgreSQL (pg-mem их не
// моделирует). Запуск: DATABASE_URL_TEST=postgres://... npx vitest run
// tests/integration/pg-real-security.test.ts. Каждый прогон — своя схема,
// удаляется в конце. Два пула = два экземпляра сервиса над одной БД.
const URL_ENV = process.env.DATABASE_URL_TEST;
const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../migrations');

function withSearchPath(url: string, schema: string): string {
  const u = new URL(url);
  u.searchParams.set('options', `-c search_path=${schema}`);
  return u.toString();
}

describe.skipIf(!URL_ENV)('Postgres: атомарность входа, OTP, nonce, лимиты', () => {
  const schema = `sec_${randomBytes(6).toString('hex')}`;
  let admin: Db;
  let a: Db; // экземпляр сервиса 1
  let b: Db; // экземпляр сервиса 2

  beforeAll(async () => {
    admin = createPool(URL_ENV!);
    await admin.query(`create schema ${schema}`);
    a = createPool(withSearchPath(URL_ENV!, schema));
    b = createPool(withSearchPath(URL_ENV!, schema));
    await runMigrations(a, migrationsDir);
  });

  afterAll(async () => {
    await a?.close();
    await b?.close();
    await admin?.query(`drop schema if exists ${schema} cascade`);
    await admin?.close();
  });

  async function count(sql: string, params: unknown[] = []): Promise<number> {
    const { rows } = await a.query<{ n: string }>(sql, params);
    return Number(rows[0]!.n);
  }

  const pid = (over: Partial<ProviderIdentity>): ProviderIdentity => ({
    provider: 'email',
    subject: 'x',
    email: 'x@example.com',
    emailVerified: true,
    profile: {},
    ...over,
  });

  it('F05: параллельные первые входы Google и кодом одним адресом с двух экземпляров → один пользователь', async () => {
    for (let round = 0; round < 10; round++) {
      const email = `race${round}@gmail.com`;
      const [g, e] = await Promise.all([
        new IdentityService(new PgIdentityRepository(a)).resolveLogin(
          pid({ provider: 'google', subject: `g-${round}`, email }),
        ),
        new IdentityService(new PgIdentityRepository(b)).resolveLogin(
          pid({ provider: 'email', subject: `code:${email}`, email }),
        ),
      ]);
      expect(g.user.id).toBe(e.user.id);
      expect(
        await count('select count(distinct user_id) as n from email_addresses where email = $1', [email]),
      ).toBe(1);
    }
    // Нет пользователей без личности (сирот).
    expect(
      await count('select count(*) as n from users u where not exists (select 1 from identities i where i.user_id = u.id)'),
    ).toBe(0);
  });

  it('F05: параллельные повторы одной личности → одна identity, без 500', async () => {
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        new IdentityService(new PgIdentityRepository(i % 2 ? a : b)).resolveLogin(
          pid({ provider: 'google', subject: 'g-same', email: 'same@gmail.com' }),
        ),
      ),
    );
    expect(new Set(results.map((r) => r.user.id)).size).toBe(1);
    expect(await count("select count(*) as n from identities where provider = 'google' and subject = 'g-same'")).toBe(1);
  });

  it('F05: сбой посреди первого входа откатывается целиком — нет пользователя-сироты', async () => {
    const before = await count('select count(*) as n from users');
    class Failing extends PgIdentityRepository {
      override async runAtomic<T>(keys: string[], fn: (repo: PgIdentityRepository) => Promise<T>): Promise<T> {
        return super.runAtomic(keys, async (repo) => {
          const failing = Object.create(repo) as PgIdentityRepository;
          failing.addIdentity = async () => {
            throw new Error('сбой после createUser');
          };
          return fn(failing);
        });
      }
    }
    await expect(
      new IdentityService(new Failing(a)).resolveLogin(pid({ provider: 'vk', subject: 'vk-orphan', email: 'orphan@example.com' })),
    ).rejects.toThrow('сбой после createUser');
    expect(await count('select count(*) as n from users')).toBe(before);
    expect(await count("select count(*) as n from email_addresses where email = 'orphan@example.com'")).toBe(0);
  });

  it('R01: сторонний адрес Google параллельно с входом владельца кодом → Google не привязан и не создал пользователя', async () => {
    const email = 'boss@corp.example';
    const [google, owner] = await Promise.allSettled([
      new IdentityService(new PgIdentityRepository(a)).resolveLogin(
        pid({ provider: 'google', subject: 'g-attacker', email, emailVerified: false }),
      ),
      new IdentityService(new PgIdentityRepository(b)).resolveLogin(
        pid({ provider: 'email', subject: `code:${email}`, email }),
      ),
    ]);
    expect(google.status).toBe('rejected');
    expect((google as PromiseRejectedResult).reason).toBeInstanceOf(EmailOwnershipRequiredError);
    expect(owner.status).toBe('fulfilled');
    expect(await count("select count(*) as n from identities where subject = 'g-attacker'")).toBe(0);
    expect(await count('select count(distinct user_id) as n from email_addresses where email = $1', [email])).toBe(1);
  });

  function provider(db: Db, code = '777777') {
    return new EmailCodeProvider(new PgLoginChallengeStore(db), new FakeMailer(), systemClock, {
      appName: 'G',
      codeTtlMinutes: 15,
      generateCode: () => code,
    });
  }

  it('F11/F10: 30 параллельных неверных проверок с двух экземпляров → ровно 5 засчитано, верный код уже не проходит', async () => {
    const { handle } = await provider(a).start({ email: 'otp@example.com', binding: 'br', client: TEST_CLIENT });
    const results = await Promise.allSettled(
      Array.from({ length: 30 }, (_, i) => provider(i % 2 ? a : b).verify({ handle, binding: 'br', client: TEST_CLIENT, code: `9${i}` })),
    );
    expect(results.every((r) => r.status === 'rejected')).toBe(true);
    const { rows } = await a.query<{ attempts: number }>(
      'select attempts from email_login_challenges where email = $1',
      ['otp@example.com'],
    );
    expect(Number(rows[0]!.attempts)).toBe(5);
    await expect(provider(b).verify({ handle, binding: 'br', client: TEST_CLIENT, code: '777777' })).rejects.toBeTruthy();
  });

  it('параллельные верные проверки одного кода → вход ровно один', async () => {
    const { handle } = await provider(a).start({ email: 'once@example.com', binding: 'br', client: TEST_CLIENT });
    const results = await Promise.allSettled(
      Array.from({ length: 5 }, (_, i) => provider(i % 2 ? a : b).verify({ handle, binding: 'br', client: TEST_CLIENT, code: '777777' })),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  });

  it('F09: параллельные переотправки не выходят за лимит и оставляют один действующий код', async () => {
    let n = 0;
    const seq = () =>
      new EmailCodeProvider(new PgLoginChallengeStore(n++ % 2 ? a : b), new FakeMailer(), systemClock, {
        appName: 'G',
        codeTtlMinutes: 15,
        generateCode: () => String(100000 + n),
      });
    const { handle } = await seq().start({ email: 'resend@example.com', binding: 'br', client: TEST_CLIENT });
    const resends = await Promise.all(Array.from({ length: 10 }, () => seq().resend({ handle, binding: 'br', client: TEST_CLIENT })));
    expect(resends.filter((r) => r !== null)).toHaveLength(3);
    const { rows } = await a.query<{ resends: number; code_hash: string }>(
      'select resends, code_hash from email_login_challenges where email = $1',
      ['resend@example.com'],
    );
    expect(rows).toHaveLength(1);
    expect(Number(rows[0]!.resends)).toBe(3);
  });

  it('P2-1: 50 параллельных переотправок одной попытки с двух экземпляров дают не больше 3 писем', async () => {
    const mailer = new FakeMailer();
    let n = 0;
    const instance = (db: Db) =>
      new EmailCodeProvider(new PgLoginChallengeStore(db), mailer, systemClock, {
        appName: 'G',
        codeTtlMinutes: 15,
        generateCode: () => String(200000 + n++),
      });
    const { handle } = await instance(a).start({ email: 'burst@example.com', binding: 'br', client: TEST_CLIENT });
    const results = await Promise.all(
      Array.from({ length: 50 }, (_, i) => instance(i % 2 ? a : b).resend({ handle, binding: 'br', client: TEST_CLIENT })),
    );
    expect(results.filter((r) => r !== null)).toHaveLength(3);
    expect(mailer.sent).toHaveLength(1 + 3);
    // Действует код последнего письма, которое заменило код.
    const { rows } = await a.query<{ resends: number }>(
      'select resends from email_login_challenges where email = $1', ['burst@example.com']);
    expect(Number(rows[0]!.resends)).toBe(3);
  });

  it('P2-1: сбой отправки возвращает слот переотправки, прежний код работает', async () => {
    const mailer = new FakeMailer();
    const codes = ['311111', '322222', '333333'];
    const provider = new EmailCodeProvider(new PgLoginChallengeStore(a), mailer, systemClock, {
      appName: 'G', codeTtlMinutes: 15, generateCode: () => codes.shift()!,
    });
    const { handle } = await provider.start({ email: 'rollback@example.com', binding: 'br', client: TEST_CLIENT });
    const send = mailer.send.bind(mailer);
    mailer.send = async () => { throw new MailDeliveryError('timeout'); };
    await expect(provider.resend({ handle, binding: 'br', client: TEST_CLIENT })).rejects.toBeInstanceOf(MailDeliveryError);
    mailer.send = send;
    expect(await provider.describe({ handle, binding: 'br' })).toMatchObject({ resendsLeft: 3 });
    await expect(provider.verify({ handle, binding: 'br', client: TEST_CLIENT, code: '311111' })).resolves.toBeTruthy();
  });

  it('F14: параллельное гашение одного nonce с двух экземпляров → ровно одно успешное', async () => {
    const nonce = await new GoogleNonceService(new PgGoogleNonceStore(a), systemClock).issue('br', 'app');
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        new GoogleNonceService(new PgGoogleNonceStore(i % 2 ? a : b), systemClock).consume(nonce, 'br', 'app'),
      ),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('F10: Postgres-лимитер с двух экземпляров параллельно пропускает ровно limit', async () => {
    const key = `burst-${randomBytes(4).toString('hex')}`;
    const results = await Promise.all(
      Array.from({ length: 40 }, (_, i) => new PgRateLimiter(i % 2 ? a : b, systemClock).hit(key, 10, 60)),
    );
    expect(results.filter((r) => r.allowed)).toHaveLength(10);
  });

  it('P3-7: refund Postgres-лимитера возвращает одно списание и не уходит ниже нуля', async () => {
    const key = `refund-${randomBytes(4).toString('hex')}`;
    const limiter = new PgRateLimiter(a, systemClock);
    await limiter.hit(key, 1, 60);
    await limiter.refund(key);
    await limiter.refund(key);
    expect((await limiter.hit(key, 1, 60)).allowed).toBe(true);
    expect((await limiter.hit(key, 1, 60)).allowed).toBe(false);
  });
});
