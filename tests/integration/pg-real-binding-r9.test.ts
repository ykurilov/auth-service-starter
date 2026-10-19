import { describe, it, expect, vi, afterEach } from 'vitest';
import type { Client } from '../../src/domain/clients/client.js';
import { SsoSessionService } from '../../src/domain/sso/sso-session-service.js';
import { PgSsoSessionStore } from '../../src/adapters/repository/pg/pg-sso-session-store.js';
import { sha256Hex } from '../../src/domain/shared/hash.js';
import { BINDING_COOKIE, DAY, forgetBindings, nextCookies, setCookie, setupPgHttp } from './pg-real-http-setup.js';

// Круг 9 через HTTP на настоящем PostgreSQL с подменёнными часами: каждая
// выданная привязка браузера действует, привязка чужой цепочки не остаётся
// у браузера после входа, а сессии приложений без цепочки (выданные до
// миграции 0013) не живут бесконечно.
const app1: Client = { id: 'app', type: 'internal', redirectUris: ['https://app.example/cb'], allowedProviders: ['email'] };
const app2: Client = { ...app1, id: 'app2', redirectUris: ['https://app2.example/cb'] };

type Setup = Awaited<ReturnType<typeof setupPgHttp>>;

const bindingOf = (s: Setup, raw: string) => new PgSsoSessionStore(s.db).findBinding(sha256Hex(raw));

afterEach(() => {
  vi.restoreAllMocks();
});

describe.skipIf(!process.env.DATABASE_URL_TEST)('Postgres + HTTP: привязки браузера, круг 9', () => {
  it('F1: две вкладки одновременно получают привязку — выход по той, что осталась у браузера, гасит цепочку', async () => {
    const s = await setupPgHttp([app1]);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      // Цепочка начата до обновления: привязки нет, у браузера только SSO-cookie.
      await forgetBindings(s.db);
      const original = SsoSessionService.prototype.bindBrowser;
      let firstBound!: () => void;
      const firstWritten = new Promise<void>((r) => (firstBound = r));
      let calls = 0;
      vi.spyOn(SsoSessionService.prototype, 'bindBrowser').mockImplementation(async function (this: SsoSessionService, ...args) {
        const token = await original.apply(this, args);
        if (++calls === 1) {
          firstBound();
          await gate;
        }
        return token;
      });
      // Первая вкладка записала привязку и задержалась с ответом, вторая
      // ответила раньше: браузер сохранит секрет из ответа первой.
      const first = s.authorize(app1, { sso: alice.cookies.sso });
      await firstWritten;
      const second = await s.authorize(app1, { sso: alice.cookies.sso });
      release();
      const last = await first;
      vi.restoreAllMocks();
      const kept = setCookie(last, BINDING_COOKIE)!.value;
      const other = setCookie(second, BINDING_COOKIE)!.value;
      expect(kept).not.toBe(other);
      // Обе выданные привязки действуют.
      expect(await bindingOf(s, kept)).not.toBeNull();
      expect(await bindingOf(s, other)).not.toBeNull();

      s.clock.advance(29 * DAY);
      const renewed = await s.refresh(alice.tokens.refresh_token);
      expect(renewed.statusCode).toBe(200);
      s.clock.advance(2 * DAY);
      // SSO-cookie истекла, у браузера — привязка из последнего ответа.
      const out = await s.logout(app1, { binding: kept });
      expect(out.statusCode).toBe(200);
      expect((await s.refresh(renewed.json().refresh_token)).statusCode).toBe(400);
      // Выход удалил все привязки цепочки.
      expect(await bindingOf(s, kept)).toBeNull();
      expect(await bindingOf(s, other)).toBeNull();
    } finally {
      release();
      await s.close();
    }
  });

  it('F1: выход по любой из привязок цепочки гасит её и удаляет все её привязки', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      await forgetBindings(s.db);
      // Ответы, потерявшие cookie привязки: каждый заход выдаёт новую.
      const a = setCookie(await s.authorize(app1, { sso: alice.cookies.sso }), BINDING_COOKIE)!.value;
      const b = setCookie(await s.authorize(app1, { sso: alice.cookies.sso }), BINDING_COOKIE)!.value;
      expect(a).not.toBe(b);
      s.clock.advance(31 * DAY);
      await s.logout(app1, { binding: a });
      expect((await s.refresh(alice.tokens.refresh_token)).statusCode).toBe(400);
      expect(await bindingOf(s, b)).toBeNull();
    } finally {
      await s.close();
    }
  });

  it('F1: привязок у цепочки не больше десяти, свежая действует; очистка удаляет просроченные', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      let latest = '';
      for (let i = 0; i < 15; i++) {
        s.clock.advance(60);
        latest = setCookie(await s.authorize(app1, { sso: alice.cookies.sso }), BINDING_COOKIE)!.value;
      }
      const count = async () => Number((await s.db.query<{ n: string }>(
        `select (select count(*) from sso_chain_bindings) + (select count(*) from sso_browser_bindings) as n`)).rows[0]!.n);
      expect(await count()).toBeLessThanOrEqual(10);
      expect(await bindingOf(s, latest)).not.toBeNull();
      // Год с лишним без заходов: привязки истекли, через 30 дней хранения
      // после истечения очистка их удаляет.
      s.clock.advance(400 * DAY);
      await new PgSsoSessionStore(s.db).deleteExpired(new Date(s.clock.now().getTime() - 30 * DAY));
      expect(await count()).toBe(0);
    } finally {
      await s.close();
    }
  });

  it('мелочь 1: заход с SSO-cookie одной цепочки и привязкой другой — привязка браузера переходит на его цепочку', async () => {
    const s = await setupPgHttp([app1, app2]);
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      const other = await s.signIn(app2, 'carol@example.test');
      const mixed = { sso: alice.cookies.sso, binding: other.cookies.binding };
      const visit = await s.authorize(app1, mixed);
      const cookies = nextCookies(mixed, visit);
      expect(cookies.binding).not.toBe(other.cookies.binding);
      // Привязка чужой цепочки у этого браузера не осталась.
      expect(await bindingOf(s, other.cookies.binding!)).toBeNull();
      expect((await bindingOf(s, cookies.binding!))?.chainId).toBe((await bindingOf(s, alice.cookies.binding!))?.chainId);
    } finally {
      await s.close();
    }
  });

  it('мелочь 1: вход с SSO-cookie одной цепочки и привязкой другой — у браузера привязка его цепочки', async () => {
    const s = await setupPgHttp([app1, app2]);
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      const other = await s.signIn(app2, 'carol@example.test');
      const again = await s.signIn(app1, 'alice@example.test', { sso: alice.cookies.sso, binding: other.cookies.binding });
      expect(again.cookies.binding).not.toBe(other.cookies.binding);
      expect(await bindingOf(s, other.cookies.binding!)).toBeNull();
      s.clock.advance(31 * DAY);
      await s.logout(app1, { binding: again.cookies.binding });
      expect((await s.refresh(again.tokens.refresh_token)).statusCode).toBe(400);
    } finally {
      await s.close();
    }
  });

  it('мелочь 2: подсаженная привязка чужой цепочки не переживает вход — её владелец не может разлогинить', async () => {
    const s = await setupPgHttp([app1, app2]);
    try {
      const mallory = await s.signIn(app2, 'mallory@example.test');
      // Второй секрет той же цепочки, про запас.
      const spare = setCookie(await s.authorize(app2, { sso: mallory.cookies.sso }), BINDING_COOKIE)!.value;
      expect(spare).not.toBe(mallory.cookies.binding);
      // Привязка подсажена в браузер жертвы по HTTP.
      const alice = await s.signIn(app1, 'alice@example.test', { binding: spare });
      expect(alice.cookies.binding).not.toBe(mallory.cookies.binding);
      expect(alice.cookies.binding).not.toBe(spare);
      await s.logout(app2, { binding: mallory.cookies.binding });
      await s.logout(app2, { binding: spare });
      expect((await s.refresh(alice.tokens.refresh_token)).statusCode).toBe(200);
      const silent = await s.authorize(app1, { sso: alice.cookies.sso }, { prompt: 'none' });
      expect(new URL(String(silent.headers.location)).searchParams.get('code')).toBeTruthy();
    } finally {
      await s.close();
    }
  });

  it('раскатка: привязку, записанную прежней версией в старую таблицу, новая находит, продлевает и гасит по ней', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      // Прежняя версия хранила одну привязку на цепочку в sso_browser_bindings.
      await s.db.query(`insert into sso_browser_bindings (chain_id, token_hash, created_at, expires_at)
        select chain_id, token_hash, created_at, expires_at from sso_chain_bindings`);
      await s.db.query('delete from sso_chain_bindings');
      s.clock.advance(20 * DAY);
      const visit = await s.authorize(app1, alice.cookies);
      expect(setCookie(visit, BINDING_COOKIE)?.value).toBe(alice.cookies.binding);
      const { rows } = await s.db.query('select 1 from sso_browser_bindings');
      expect(rows).toHaveLength(0);
      const first = await s.refresh(alice.tokens.refresh_token);
      s.clock.advance(29 * DAY);
      const renewed = await s.refresh(first.json().refresh_token);
      expect(renewed.statusCode).toBe(200);
      // SSO-cookie истекла на 50-й день; сессию приложения держит привязка.
      s.clock.advance(2 * DAY);
      await s.logout(app1, { binding: alice.cookies.binding });
      expect((await s.refresh(renewed.json().refresh_token)).statusCode).toBe(400);
    } finally {
      await s.close();
    }
  });

  describe('F2: сессии приложений без цепочки (выданы до миграции 0013)', () => {
    async function legacySignIn(s: Setup, c: Client, email: string) {
      const signed = await s.signIn(c, email);
      await s.db.query('update sessions set sso_chain_id = null');
      await forgetBindings(s.db);
      return signed;
    }

    it('продлеваются не дальше своего срока на момент обновления: дальше — новый вход', async () => {
      const s = await setupPgHttp([app1]);
      try {
        const alice = await legacySignIn(s, app1, 'alice@example.test');
        s.clock.advance(10 * DAY);
        const first = await s.refresh(alice.tokens.refresh_token);
        expect(first.statusCode).toBe(200);
        s.clock.advance(19 * DAY);
        const second = await s.refresh(first.json().refresh_token);
        expect(second.statusCode).toBe(200);
        s.clock.advance(2 * DAY);
        expect((await s.refresh(second.json().refresh_token)).statusCode).toBe(400);
      } finally {
        await s.close();
      }
    });

    it('после выхода по привязке и смены аккаунта в браузере живут не дольше своего срока', async () => {
      const s = await setupPgHttp([app1, app2]);
      try {
        const alice = await legacySignIn(s, app1, 'alice@example.test');
        const visit = await s.authorize(app1, { sso: alice.cookies.sso });
        const cookies = nextCookies({ sso: alice.cookies.sso }, visit);
        await s.signIn(app2, 'bob@example.test', cookies);
        s.clock.advance(20 * DAY);
        const r = await s.refresh(alice.tokens.refresh_token);
        expect(r.statusCode).toBe(200);
        s.clock.advance(11 * DAY);
        expect((await s.refresh(r.json().refresh_token)).statusCode).toBe(400);
      } finally {
        await s.close();
      }
    });
  });
});
