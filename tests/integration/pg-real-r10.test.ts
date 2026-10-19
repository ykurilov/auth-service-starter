import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, vi, afterEach } from 'vitest';
import type { Client } from '../../src/domain/clients/client.js';
import type { Db } from '../../src/adapters/db/pool.js';
import { PgSsoSessionStore } from '../../src/adapters/repository/pg/pg-sso-session-store.js';
import { pgCleanupService } from '../../src/adapters/repository/pg/pg-cleanup.js';
import { sha256Hex } from '../../src/domain/shared/hash.js';
import { DAY, codeOf, setupPgHttp, type BrowserCookies } from './pg-real-http-setup.js';

// Круг 10 через HTTP на настоящем PostgreSQL с подменёнными часами: выход
// не трогает другие браузеры пользователя, цепочки разных браузеров не дают
// взаимных блокировок, история refresh-токенов не растёт бесконечно, смена
// аккаунта начинает новую цепочку, миграция 0019 не теряет привязки.
const app1: Client = { id: 'app', type: 'internal', redirectUris: ['https://app.example/cb'], allowedProviders: ['email'] };
const migrationsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../migrations');

type Setup = Awaited<ReturnType<typeof setupPgHttp>>;

const chainOfBinding = async (s: Setup, raw: string) =>
  (await new PgSsoSessionStore(s.db).findBinding(sha256Hex(raw)))!.chainId;

function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => (open = resolve));
  return { opened, open };
}

// Кто-то в базе ждёт блокировку (advisory или строку).
async function someoneWaits(db: Db): Promise<boolean> {
  const { rows } = await db.query<{ n: string }>('select count(*) as n from pg_locks where not granted');
  return Number(rows[0]!.n) > 0;
}

// Ждём условия без жёстких пауз: опрос раз в 5 мс, не дольше 5 с.
async function until(check: () => Promise<boolean> | boolean, what: string): Promise<void> {
  for (let i = 0; i < 1000; i++) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(`не дождались: ${what}`);
}

// Барьер для двух транзакций: первая, взявшая блокировку цепочки (или
// удалившая привязку, если pauseAfter = 'deleteBinding'), ждёт, пока вторая
// либо возьмёт свою блокировку, либо встанет в очередь за чужой. Так обе
// успевают захватить что-то до того, как первая пойдёт дальше: при обратном
// порядке блокировок это взаимная блокировка.
function holdFirstUntilSecondArrives(s: Setup, pauseAfter: 'lockChain' | 'deleteBinding') {
  const lockOriginal = PgSsoSessionStore.prototype.lockChain;
  const deleteOriginal = PgSsoSessionStore.prototype.deleteBinding;
  let first: PgSsoSessionStore | null = null;
  let paused = false;
  let secondLocked = false;
  const pause = async (store: PgSsoSessionStore) => {
    if (paused || store !== first) return;
    paused = true;
    await until(async () => secondLocked || (await someoneWaits(s.db)), 'вторая транзакция дошла до блокировки');
  };
  vi.spyOn(PgSsoSessionStore.prototype, 'lockChain').mockImplementation(async function (this: PgSsoSessionStore, chainId) {
    if (pauseAfter === 'lockChain') first ??= this;
    await lockOriginal.call(this, chainId);
    if (first !== null && this !== first) secondLocked = true;
    if (pauseAfter === 'lockChain') await pause(this);
  });
  vi.spyOn(PgSsoSessionStore.prototype, 'deleteBinding').mockImplementation(async function (this: PgSsoSessionStore, hash) {
    if (pauseAfter === 'deleteBinding') first ??= this;
    await deleteOriginal.call(this, hash);
    if (pauseAfter === 'deleteBinding') await pause(this);
  });
  return { started: () => first !== null };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe.skipIf(!process.env.DATABASE_URL_TEST)('Postgres + HTTP: круг 10', () => {
  it('H1: «Выйти» в одном браузере не трогает другой браузер того же пользователя', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const laptop = await s.signIn(app1, 'alice@example.test');
      const phone = await s.signIn(app1, 'alice@example.test');
      expect((await s.logout(app1, laptop.cookies)).statusCode).toBe(200);

      expect((await s.refresh(laptop.tokens.refresh_token)).statusCode).toBe(400);
      expect((await s.refresh(phone.tokens.refresh_token)).statusCode).toBe(200);
      // SSO другого браузера жива: тихий вход выдаёт код.
      const silent = await s.authorize(app1, phone.cookies, { prompt: 'none' });
      expect(silent.statusCode).toBe(302);
      expect(codeOf(silent)).toBeTruthy();
    } finally {
      await s.close();
    }
  });

  it('G2: заход на /authorize и выход с SSO-cookie одной цепочки и привязкой другой не блокируют друг друга', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const a = await s.signIn(app1, 'alice@example.test');
      const b = await s.signIn(app1, 'bob@example.test');
      const mixed: BrowserCookies = { sso: a.cookies.sso, binding: b.cookies.binding };
      const barrier = holdFirstUntilSecondArrives(s, 'deleteBinding');
      const visit = s.authorize(app1, mixed, { prompt: 'none' });
      await until(barrier.started, 'заход удалил привязку чужой цепочки');
      const out = s.logout(app1, mixed);
      const [visited, loggedOut] = await Promise.all([visit, out]);
      expect(visited.statusCode).not.toBe(500);
      expect(loggedOut.statusCode).toBe(200);
      expect((await s.refresh(a.tokens.refresh_token)).statusCode).toBe(400);
    } finally {
      await s.close();
    }
  });

  it('G2: вход и выход с SSO-cookie одной цепочки и привязкой другой не блокируют друг друга', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const a = await s.signIn(app1, 'alice@example.test');
      const b = await s.signIn(app1, 'bob@example.test');
      const mixed: BrowserCookies = { sso: a.cookies.sso, binding: b.cookies.binding };
      const barrier = holdFirstUntilSecondArrives(s, 'deleteBinding');
      const login = s.codeLogin(app1, 'alice@example.test', mixed);
      await until(barrier.started, 'вход удалил привязку чужой цепочки');
      const out = s.logout(app1, mixed);
      const [{ verify }, loggedOut] = await Promise.all([login, out]);
      expect(verify.statusCode).toBe(302);
      expect(loggedOut.statusCode).toBe(200);
    } finally {
      await s.close();
    }
  });

  it('G2: два выхода с противоположными парами cookie не блокируют друг друга', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const a = await s.signIn(app1, 'alice@example.test');
      const b = await s.signIn(app1, 'bob@example.test');
      holdFirstUntilSecondArrives(s, 'lockChain');
      const results = await Promise.all([
        s.logout(app1, { sso: a.cookies.sso, binding: b.cookies.binding }),
        s.logout(app1, { sso: b.cookies.sso, binding: a.cookies.binding }),
      ]);
      expect(results.map((r) => r.statusCode)).toEqual([200, 200]);
      expect((await s.refresh(a.tokens.refresh_token)).statusCode).toBe(400);
      expect((await s.refresh(b.tokens.refresh_token)).statusCode).toBe(400);
    } finally {
      await s.close();
    }
  });

  it('G3: история refresh-токенов живой сессии ограничена, а давно погашенный токен по-прежнему отзывает сессию', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const cleanup = pgCleanupService(s.db, s.clock);
      const alice = await s.signIn(app1, 'alice@example.test');
      const first = alice.tokens.refresh_token;
      let token = first;
      for (let i = 0; i < 120; i++) {
        s.clock.advance(20 * DAY);
        // Заход на страницы входа продлевает SSO и привязку браузера.
        expect((await s.authorize(app1, alice.cookies, { prompt: 'none' })).statusCode).toBe(302);
        const renewed = await s.refresh(token);
        expect(renewed.statusCode).toBe(200);
        token = renewed.json().refresh_token;
        await cleanup.runOnce();
      }
      const { rows } = await s.db.query<{ n: string }>('select count(*) as n from refresh_tokens');
      expect(Number(rows[0]!.n)).toBeLessThanOrEqual(3);
      // Строки первого токена нет, но его предъявление — повтор: новых токенов
      // нет, сессия отозвана, и текущий токен тоже больше не действует.
      const reused = await s.refresh(first);
      expect(reused.statusCode).toBe(400);
      expect((await s.refresh(token)).statusCode).toBe(400);
    } finally {
      await s.close();
    }
  }, 60_000);

  it('G3: очистка не трогает токены свежее часа — повтор в окне grace по-прежнему отдаёт текущий токен', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const cleanup = pgCleanupService(s.db, s.clock);
      const alice = await s.signIn(app1, 'alice@example.test');
      let token = alice.tokens.refresh_token;
      for (let i = 0; i < 10; i++) {
        s.clock.advance(60);
        token = (await s.refresh(token)).json().refresh_token;
      }
      const previous = token;
      const current = (await s.refresh(previous)).json().refresh_token as string;
      await cleanup.runOnce();
      const { rows } = await s.db.query<{ n: string }>('select count(*) as n from refresh_tokens');
      expect(Number(rows[0]!.n)).toBe(12);
      // Ответ потерялся — повтор того же запроса в окне grace.
      const retry = await s.refresh(previous);
      expect(retry.statusCode).toBe(200);
      expect(retry.json().refresh_token).toBe(current);
    } finally {
      await s.close();
    }
  });

  it('G3: отзыв (RFC 7009) по давно погашенному токену, чью строку удалила очистка, гасит сессию', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const cleanup = pgCleanupService(s.db, s.clock);
      const alice = await s.signIn(app1, 'alice@example.test');
      const first = alice.tokens.refresh_token;
      let token = first;
      for (let i = 0; i < 5; i++) {
        s.clock.advance(DAY);
        token = (await s.refresh(token)).json().refresh_token;
      }
      s.clock.advance(2 * DAY);
      await cleanup.runOnce();
      const { rows } = await s.db.query('select 1 from refresh_tokens where token_hash = $1', [sha256Hex(first)]);
      expect(rows).toEqual([]);
      const revoked = await s.app.inject({ method: 'POST', url: '/oauth/revoke', payload: { token: first, client_id: app1.id } });
      expect(revoked.statusCode).toBe(200);
      expect((await s.refresh(token)).statusCode).toBe(400);
    } finally {
      await s.close();
    }
  });

  it('G3: сессия с токеном прежнего формата получает семейство при refresh; повтор старого токена отзывает её и после очистки', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const cleanup = pgCleanupService(s.db, s.clock);
      const alice = await s.signIn(app1, 'alice@example.test');
      // Токен, выданный до миграции 0020: случайный, без семейства.
      const legacy = randomBytes(32).toString('base64url');
      await s.db.query('update refresh_tokens set token_hash = $1, family_hash = null where token_hash = $2',
        [sha256Hex(legacy), sha256Hex(alice.tokens.refresh_token)]);
      let token = legacy;
      for (let i = 0; i < 6; i++) {
        s.clock.advance(DAY);
        const renewed = await s.refresh(token);
        expect(renewed.statusCode).toBe(200);
        token = renewed.json().refresh_token;
        expect(token).toMatch(/^[A-Za-z0-9_-]{22}\./);
        await cleanup.runOnce();
      }
      const { rows } = await s.db.query<{ legacy: boolean }>('select family_hash is null as legacy from refresh_tokens');
      // Строка прежнего формата остаётся (только по ней узнаётся её повтор), из
      // новых — три последних.
      expect(rows.filter((r) => r.legacy)).toHaveLength(1);
      expect(rows.filter((r) => !r.legacy)).toHaveLength(3);
      expect((await s.refresh(legacy)).statusCode).toBe(400);
      expect((await s.refresh(token)).statusCode).toBe(400);
    } finally {
      await s.close();
    }
  }, 20_000);

  it('смена аккаунта начинает новую цепочку: прежний владелец подсаженной привязки не разлогинивает вошедшего', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const mallory = await s.signIn(app1, 'mallory@example.test');
      s.clock.advance(120);
      // Алиса входит в браузере, куда подсажена привязка Мэллори.
      const alice = await s.signIn(app1, 'alice@example.test', { binding: mallory.cookies.binding });
      expect(await chainOfBinding(s, alice.cookies.binding!)).not.toBe(
        (await s.db.query<{ chain_id: string }>(
          'select chain_id from sso_sessions where token_hash = $1', [sha256Hex(mallory.cookies.sso!)])).rows[0]!.chain_id,
      );
      // Ни привязка, ни SSO-cookie Мэллори не гасят Алису.
      expect((await s.logout(app1, { binding: mallory.cookies.binding })).statusCode).toBe(200);
      const refreshed = await s.refresh(alice.tokens.refresh_token);
      expect(refreshed.statusCode).toBe(200);
      s.clock.advance(120);
      await s.signIn(app1, 'mallory@example.test', { sso: mallory.cookies.sso });
      expect((await s.logout(app1, { sso: mallory.cookies.sso })).statusCode).toBe(200);
      const after = await s.refresh(refreshed.json().refresh_token);
      expect(after.statusCode).toBe(200);
      // Выход Алисы в её браузере гасит её сессию.
      expect((await s.logout(app1, alice.cookies)).statusCode).toBe(200);
      expect((await s.refresh(after.json().refresh_token)).statusCode).toBe(400);
    } finally {
      await s.close();
    }
  }, 20_000);

  it('миграция 0019 не теряет привязку, которую копия прежней версии записала во время переноса', async () => {
    const s = await setupPgHttp([app1]);
    const release = gate();
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      const chainId = await chainOfBinding(s, alice.cookies.binding!);
      // База до 0019: привязки в старой таблице, новой нет.
      await s.db.query('insert into sso_browser_bindings select chain_id, token_hash, created_at, expires_at from sso_chain_bindings');
      await s.db.query('drop table sso_chain_bindings');
      const sql = await readFile(path.join(migrationsDir, '0019_sso_chain_bindings.sql'), 'utf8');
      const dml = sql.indexOf('insert into sso_chain_bindings');
      const lockKey = '821987650010';
      const held = gate();
      const blocker = s.db.withConnection(async (conn) => {
        await conn.query('select pg_advisory_lock($1::bigint)', [lockKey]);
        held.open();
        await release.opened;
        await conn.query('select pg_advisory_unlock($1::bigint)', [lockKey]);
      });
      await held.opened;
      // Перенос из миграции в одной транзакции; тестовый триггер задерживает
      // копирование, пока копия прежней версии не запишет новую привязку.
      const migration = s.db.withTransaction(async (tx) => {
        await tx.query(sql.slice(0, dml));
        await tx.query(`create function r10_pause() returns trigger language plpgsql as $$
            begin perform pg_advisory_xact_lock(${lockKey}); return new; end $$;
          create trigger r10_pause before insert on sso_chain_bindings for each row execute function r10_pause()`);
        await tx.query(sql.slice(dml));
        await tx.query('drop trigger r10_pause on sso_chain_bindings; drop function r10_pause()');
      });
      await until(() => someoneWaits(s.db), 'миграция ждёт на копировании');
      const fresh = 'old-copy-fresh-binding-secret';
      // Запись копии прежней версии (0018): одна привязка на цепочку, upsert.
      await s.db.query(
        `insert into sso_browser_bindings (chain_id, token_hash, created_at, expires_at) values ($1, $2, $3, $4)
           on conflict (chain_id) do update set token_hash = excluded.token_hash,
             created_at = excluded.created_at, expires_at = excluded.expires_at`,
        [chainId, sha256Hex(fresh), s.clock.now(), new Date(s.clock.now().getTime() + 365 * DAY * 1000)],
      );
      release.open();
      await blocker;
      await migration;
      const store = new PgSsoSessionStore(s.db);
      expect(await store.findBinding(sha256Hex(fresh))).not.toBeNull();
      // SSO-cookie истекла, у браузера только свежая привязка, а сессию
      // приложения продлил refresh прежней версии: выход по привязке её гасит.
      await s.db.query('update sessions set expires_at = $1', [new Date(s.clock.now().getTime() + 59 * DAY * 1000)]);
      s.clock.advance(31 * DAY);
      expect((await s.logout(app1, { binding: fresh })).statusCode).toBe(200);
      expect((await s.refresh(alice.tokens.refresh_token)).statusCode).toBe(400);
    } finally {
      release.open();
      await s.close();
    }
  }, 15_000);
});
