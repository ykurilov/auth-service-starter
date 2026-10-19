import { describe, it, expect } from 'vitest';
import type { Client } from '../../src/domain/clients/client.js';
import { PgSsoSessionStore } from '../../src/adapters/repository/pg/pg-sso-session-store.js';
import { sha256Hex } from '../../src/domain/shared/hash.js';
import { BINDING_COOKIE, DAY, forgetBindings, nextCookies, setCookie, setupPgHttp } from './pg-real-http-setup.js';

// E2 через HTTP на настоящем PostgreSQL с подменёнными часами. SSO-cookie
// живёт 30 дней с последнего захода на страницы входа, а сессия приложения
// продлевается refresh без участия браузера. «Выйти» и смена аккаунта должны
// доставать сессии приложений этого браузера, пока они живы.
const app1: Client = { id: 'app', type: 'internal', redirectUris: ['https://app.example/cb'], allowedProviders: ['email'] };
const app2: Client = { ...app1, id: 'app2', redirectUris: ['https://app2.example/cb'] };

describe.skipIf(!process.env.DATABASE_URL_TEST)('Postgres + HTTP: привязка браузера к цепочке SSO', () => {
  it('вход выдаёт долгоживущую cookie привязки: httpOnly, без права входа', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const { verify } = await s.codeLogin(app1, 'alice@example.test');
      const binding = setCookie(verify, BINDING_COOKIE);
      expect(binding?.value).toBeTruthy();
      expect(binding?.httpOnly).toBe(true);
      expect(binding?.path).toBe('/');
      expect(binding?.sameSite).toBe('Lax');
      // Не короче сессии приложения.
      expect(binding!.maxAge!).toBeGreaterThanOrEqual(30 * DAY);
      // Одна привязка не входит: ни экрана согласия, ни тихого кода.
      const page = await s.authorize(app1, { binding: binding!.value });
      expect(page.body).not.toContain('/authorize/confirm');
      const silent = await s.authorize(app1, { binding: binding!.value }, { prompt: 'none' });
      expect(new URL(String(silent.headers.location)).searchParams.get('error')).toBe('login_required');
    } finally {
      await s.close();
    }
  });

  it('«Выйти» после истечения SSO-cookie гасит сессии приложений браузера', async () => {
    const s = await setupPgHttp([app1, app2]);
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      s.clock.advance(29 * DAY);
      const renewed = await s.refresh(alice.tokens.refresh_token);
      expect(renewed.statusCode).toBe(200);
      s.clock.advance(2 * DAY);
      // Браузер выбросил SSO-cookie по Max-Age, привязка осталась.
      const out = await s.logout(app2, { binding: alice.cookies.binding });
      expect(out.statusCode).toBe(200);
      expect(out.body).toContain('Вы вышли из аккаунта');
      expect(setCookie(out, BINDING_COOKIE)?.value).toBe('');
      expect((await s.refresh(renewed.json().refresh_token)).statusCode).toBe(400);
    } finally {
      await s.close();
    }
  });

  it('смена аккаунта после истечения SSO-cookie гасит прежний аккаунт в приложениях браузера', async () => {
    const s = await setupPgHttp([app1, app2]);
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      s.clock.advance(29 * DAY);
      const renewed = await s.refresh(alice.tokens.refresh_token);
      expect(renewed.statusCode).toBe(200);
      s.clock.advance(2 * DAY);
      const bob = await s.signIn(app2, 'bob@example.test', { binding: alice.cookies.binding });
      // Смена аккаунта выдаёт новую привязку, прежние привязки цепочки удалены.
      expect(bob.cookies.binding).not.toBe(alice.cookies.binding);
      expect(await new PgSsoSessionStore(s.db).findBinding(sha256Hex(alice.cookies.binding!))).toBeNull();
      const old = await s.refresh(renewed.json().refresh_token);
      expect(old.statusCode).toBe(400);
      expect((await s.refresh(bob.tokens.refresh_token)).statusCode).toBe(200);
    } finally {
      await s.close();
    }
  });

  it('чужая или выдуманная привязка не гасит сессии другого браузера', async () => {
    const s = await setupPgHttp([app1, app2]);
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      const bob = await s.signIn(app2, 'bob@example.test');
      expect(bob.cookies.binding).not.toBe(alice.cookies.binding);
      s.clock.advance(20 * DAY);
      const aliceRenewed = await s.refresh(alice.tokens.refresh_token);
      const bobRenewed = await s.refresh(bob.tokens.refresh_token);
      s.clock.advance(11 * DAY);
      await s.logout(app2, { binding: bob.cookies.binding });
      await s.logout(app2, { binding: 'made-up-value' });
      expect((await s.refresh(aliceRenewed.json().refresh_token)).statusCode).toBe(200);
      expect((await s.refresh(bobRenewed.json().refresh_token)).statusCode).toBe(400);
    } finally {
      await s.close();
    }
  });

  it('выход по одной привязке гасит этот браузер, но не другие устройства того же пользователя', async () => {
    const s = await setupPgHttp([app1, app2]);
    try {
      const laptop = await s.signIn(app1, 'alice@example.test');
      const phone = await s.signIn(app2, 'alice@example.test');
      await s.logout(app1, { binding: laptop.cookies.binding });
      expect((await s.refresh(laptop.tokens.refresh_token)).statusCode).toBe(400);
      expect((await s.refresh(phone.tokens.refresh_token)).statusCode).toBe(200);
      const silent = await s.authorize(app1, { sso: laptop.cookies.sso }, { prompt: 'none' });
      expect(new URL(String(silent.headers.location)).searchParams.get('error')).toBe('login_required');
      const { rows } = await s.db.query('select 1 from sso_chain_bindings');
      expect(rows).toHaveLength(1);
    } finally {
      await s.close();
    }
  });

  it('сессия приложения не переживает привязку: без заходов на вход — не дольше её срока', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      const ttlDays = setCookie((await s.codeLogin(app1, 'probe@example.test')).verify, BINDING_COOKIE)!.maxAge! / DAY;
      let token = alice.tokens.refresh_token;
      let day = 0;
      while (day + 20 < ttlDays) {
        s.clock.advance(20 * DAY);
        day += 20;
        const r = await s.refresh(token);
        expect(r.statusCode).toBe(200);
        token = r.json().refresh_token;
      }
      s.clock.advance((ttlDays - day + 1) * DAY);
      expect((await s.refresh(token)).statusCode).toBe(400);
    } finally {
      await s.close();
    }
  });

  it('заход на страницы входа продлевает привязку вместе с SSO-cookie', async () => {
    const s = await setupPgHttp([app1]);
    try {
      const alice = await s.signIn(app1, 'alice@example.test');
      s.clock.advance(20 * DAY);
      const visit = await s.authorize(app1, alice.cookies);
      expect(visit.body).toContain('/authorize/confirm');
      const renewed = setCookie(visit, BINDING_COOKIE);
      expect(renewed?.value).toBe(alice.cookies.binding);
      expect(renewed!.maxAge!).toBeGreaterThanOrEqual(30 * DAY);
    } finally {
      await s.close();
    }
  });

  describe('обновление: сессии и cookie, выданные до правки', () => {
    // Состояние до правки: привязок нет, у браузера только SSO-cookie.
    async function legacySignIn(s: Awaited<ReturnType<typeof setupPgHttp>>, email: string) {
      const signed = await s.signIn(app1, email);
      await forgetBindings(s.db);
      return { tokens: signed.tokens, cookies: { sso: signed.cookies.sso } };
    }

    it('заход с живой SSO-cookie выдаёт привязку, и выход после её истечения работает', async () => {
      const s = await setupPgHttp([app1, app2]);
      try {
        const alice = await legacySignIn(s, 'alice@example.test');
        s.clock.advance(10 * DAY);
        const visit = await s.authorize(app2, alice.cookies);
        const cookies = nextCookies(alice.cookies, visit);
        expect(cookies.binding).toBeTruthy();
        const first = await s.refresh(alice.tokens.refresh_token);
        s.clock.advance(25 * DAY);
        const renewed = await s.refresh(first.json().refresh_token);
        expect(renewed.statusCode).toBe(200);
        // SSO-сессия цепочки истекла на 40-й день, а сессию приложения
        // продлевает привязка: выход по ней её отзывает.
        s.clock.advance(10 * DAY);
        await s.logout(app2, { binding: cookies.binding });
        const { rows } = await s.db.query<{ revoked_at: Date | null }>('select revoked_at from sessions');
        expect(rows).toHaveLength(1);
        expect(rows[0]!.revoked_at).not.toBeNull();
        expect((await s.refresh(renewed.json().refresh_token)).statusCode).toBe(400);
      } finally {
        await s.close();
      }
    });

    it('без захода сессия приложения кончается вместе с SSO-cookie, а не живёт вне досягаемости', async () => {
      const s = await setupPgHttp([app1]);
      try {
        const alice = await legacySignIn(s, 'alice@example.test');
        s.clock.advance(29 * DAY);
        const renewed = await s.refresh(alice.tokens.refresh_token);
        expect(renewed.statusCode).toBe(200);
        s.clock.advance(2 * DAY);
        expect((await s.refresh(renewed.json().refresh_token)).statusCode).toBe(400);
      } finally {
        await s.close();
      }
    });

    it('выход по старой живой SSO-cookie без привязки работает как раньше', async () => {
      const s = await setupPgHttp([app1]);
      try {
        const alice = await legacySignIn(s, 'alice@example.test');
        await s.logout(app1, alice.cookies);
        expect((await s.refresh(alice.tokens.refresh_token)).statusCode).toBe(400);
      } finally {
        await s.close();
      }
    });
  });
});
