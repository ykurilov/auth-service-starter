import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
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
import { MailDeliveryError, type OutgoingEmail } from '../../src/ports/mailer.js';
import { InvalidCredentialsError, UnconfirmedCodeDeliveryError } from '../../src/domain/email-login/errors.js';
import { systemClock } from '../../src/ports/clock.js';
import { sha256Hex as sha256Of } from '../../src/domain/shared/hash.js';
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
    mailer.send = async () => { throw new MailDeliveryError('422', 'rejected'); };
    await expect(provider.resend({ handle, binding: 'br', client: TEST_CLIENT })).rejects.toBeInstanceOf(MailDeliveryError);
    mailer.send = send;
    expect(await provider.describe({ handle, binding: 'br' })).toMatchObject({ resendsLeft: 3 });
    await expect(provider.verify({ handle, binding: 'br', client: TEST_CLIENT, code: '311111' })).resolves.toBeTruthy();
  });

  // Письмо уходит только по команде теста: барьер, задающий порядок ответов
  // провайдера на параллельные переотправки с двух экземпляров.
  function heldMailer() {
    const held: { email: OutgoingEmail; deliver: () => void; fail: (err: Error) => void }[] = [];
    const mailer = new FakeMailer();
    mailer.send = (email) =>
      new Promise<void>((resolve, reject) => {
        held.push({ email, deliver: () => { mailer.sent.push(email); resolve(); }, fail: reject });
      });
    return { mailer, held };
  }
  const codeOf = (email: OutgoingEmail) => /\d{6}/.exec(email.text)![0];

  it('R4-A1: таймауты переотправки на Postgres — слот потрачен, действует код последнего письма', async () => {
    const mailer = new FakeMailer();
    let n = 0;
    const instance = (db: Db) =>
      new EmailCodeProvider(new PgLoginChallengeStore(db), mailer, systemClock, {
        appName: 'G', codeTtlMinutes: 15, generateCode: () => String(410000 + n++),
      });
    const { handle } = await instance(a).start({ email: 'timeout@example.com', binding: 'br', client: TEST_CLIENT });
    const send = mailer.send.bind(mailer);
    mailer.send = async (email) => { await send(email); throw new MailDeliveryError('timeout'); };
    for (let i = 0; i < 6; i++) {
      const r = await instance(i % 2 ? a : b).resend({ handle, binding: 'br', client: TEST_CLIENT }).catch((e: unknown) => e);
      if (i < 3) expect(r).toBeInstanceOf(UnconfirmedCodeDeliveryError);
      else expect(r).toBeNull();
    }
    expect(mailer.sent).toHaveLength(1 + 3);
    const last = codeOf(mailer.sent[3]!);
    await expect(instance(a).verify({ handle, binding: 'br', client: TEST_CLIENT, code: codeOf(mailer.sent[2]!) }))
      .rejects.toBeInstanceOf(InvalidCredentialsError);
    await expect(instance(b).verify({ handle, binding: 'br', client: TEST_CLIENT, code: last })).resolves.toBeTruthy();
  });

  it('R4-A2: две переотправки с двух экземпляров — опоздавшее письмо раннего слота не затирает новый код', async () => {
    const { mailer, held } = heldMailer();
    let n = 0;
    const instance = (db: Db) =>
      new EmailCodeProvider(new PgLoginChallengeStore(db), mailer, systemClock, {
        appName: 'G', codeTtlMinutes: 15, generateCode: () => String(420000 + n++),
      });
    const start = instance(a).start({ email: 'race@example.com', binding: 'br', client: TEST_CLIENT });
    await vi.waitFor(() => expect(held).toHaveLength(1));
    held[0]!.deliver();
    const { handle } = await start;
    const first = instance(a).resend({ handle, binding: 'br', client: TEST_CLIENT });
    await vi.waitFor(() => expect(held).toHaveLength(2));
    const second = instance(b).resend({ handle, binding: 'br', client: TEST_CLIENT });
    await vi.waitFor(() => expect(held).toHaveLength(3));
    held[2]!.deliver();
    expect(await second).toEqual({ email: 'race@example.com' });
    held[1]!.deliver();
    expect(await first).toEqual({ email: 'race@example.com' });
    await expect(instance(a).verify({ handle, binding: 'br', client: TEST_CLIENT, code: codeOf(held[1]!.email) }))
      .rejects.toBeInstanceOf(InvalidCredentialsError);
    await expect(instance(b).verify({ handle, binding: 'br', client: TEST_CLIENT, code: codeOf(held[2]!.email) }))
      .resolves.toBeTruthy();
  });

  it('R4-A2: одновременная запись кодов двух слотов — побеждает более новый слот', async () => {
    // Обе записи кода стартуют, пока строка заблокирована третьей транзакцией:
    // Postgres перепроверяет условие слота на свежей версии строки.
    const provider = new EmailCodeProvider(new PgLoginChallengeStore(a), new FakeMailer(), systemClock, {
      appName: 'G', codeTtlMinutes: 15, generateCode: () => '430000',
    });
    const { handle } = await provider.start({ email: 'locked@example.com', binding: 'br', client: TEST_CLIENT });
    const storeA = new PgLoginChallengeStore(a);
    const storeB = new PgLoginChallengeStore(b);
    const one = await storeA.reserveResend(sha256Of(`challenge:${handle}`), sha256Of('binding:br'), new Date());
    const two = await storeB.reserveResend(sha256Of(`challenge:${handle}`), sha256Of('binding:br'), new Date());
    expect([one!.lastSlot, two!.lastSlot]).toEqual([1, 2]);
    const locker = createPool(withSearchPath(URL_ENV!, schema));
    try {
      await locker.query('begin');
      await locker.query('select id from email_login_challenges where id = $1 for update', [one!.id]);
      const expires = new Date(Date.now() + 15 * 60_000);
      const waiting = () => count(
        `select count(*) as n from pg_stat_activity
          where datname = current_database() and wait_event_type = 'Lock'
            and query like 'update email_login_challenges set code_hash%'`,
      );
      // Очередь на блокировку: сначала запись слота 2, за ней слота 1.
      const newer = storeB.replaceCode(two!.id, 2, 'hash-slot-2', expires, new Date());
      await vi.waitFor(async () => expect(await waiting()).toBe(1));
      const older = storeA.replaceCode(one!.id, 1, 'hash-slot-1', expires, new Date());
      await vi.waitFor(async () => expect(await waiting()).toBe(2));
      await locker.query('commit');
      expect(await newer).toBe(true);
      expect(await older).toBe(false);
    } finally {
      await locker.close();
    }
    const { rows } = await a.query<{ code_hash: string; code_slot: number }>(
      'select code_hash, code_slot from email_login_challenges where email = $1', ['locked@example.com']);
    expect(rows[0]).toEqual({ code_hash: 'hash-slot-2', code_slot: 2 });
  });

  it('R5-B1: resume на Postgres — попытка браузера находится другим экземпляром по адресу и регистрации', async () => {
    const mk = (db: Db) => new EmailCodeProvider(new PgLoginChallengeStore(db), new FakeMailer(), systemClock, {
      appName: 'Auth Service', codeTtlMinutes: 15, generateCode: () => '515151',
    });
    const started = await mk(a).start({ email: 'resume@example.com', binding: 'br-resume', client: TEST_CLIENT });
    await mk(a).start({ email: 'resume@example.com', binding: 'br-resume', client: { id: 'app' } });
    expect(await mk(b).resume({ email: 'resume@example.com', binding: 'br-resume', client: TEST_CLIENT })).toEqual(started);
    expect((await mk(b).resume({ email: 'resume@example.com', binding: 'br-resume', client: { id: 'app' } }))?.handle)
      .not.toBe(started.handle);
    expect(await mk(b).resume({ email: 'resume@example.com', binding: 'br-other', client: TEST_CLIENT })).toBeNull();
    await mk(b).verify({ handle: started.handle, binding: 'br-resume', client: TEST_CLIENT, code: '515151' });
    expect(await mk(a).resume({ email: 'resume@example.com', binding: 'br-resume', client: TEST_CLIENT })).toBeNull();
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
