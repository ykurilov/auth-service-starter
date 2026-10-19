import { describe, it, expect, vi } from 'vitest';
import { createAuthMiddleware } from '../../module/server/nextjs.js';
import { seal, unseal } from '../../module/server/core/cookie-seal.js';
import { parseCookies } from '../../module/server/cookies.js';
import { getUser, silentCheckDone } from '../../module/server/server.js';
import { cookieNamesFor } from './helpers.js';

const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1';
const env = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: 'https://app.test', AUTH_COOKIE_SECRET: SECRET };
const SESSION_COOKIE = cookieNamesFor(env).session;

function fakeJwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(unescape(encodeURIComponent(JSON.stringify(o))))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${b64({ alg: 'RS256' })}.${b64(payload)}.sig`;
}
function setCookies(res: Response): string[] {
  return (res.headers as unknown as { getSetCookie(): string[] }).getSetCookie();
}
async function sessionCookie(expiresInMs: number, refreshToken = 'r1') {
  const data = {
    user: { id: 'u1', roles: [] },
    accessToken: fakeJwt({ sub: 'u1' }),
    refreshToken,
    accessTokenExpiresAt: Date.now() + expiresInMs,
  };
  return `${SESSION_COOKIE}=${await seal(data, SECRET)}`;
}

// В Next.js приложение передаёт () => NextResponse.next(); в тестах — обычный 200.
const pass = () => new Response(null, { status: 200 });

describe('createAuthMiddleware', () => {
  it('свежий access (>120с) -> отдаёт ответ next() без изменений, refresh не вызывается', async () => {
    const fetchImpl = vi.fn(async () => new Response('')) as unknown as typeof fetch;
    const mw = createAuthMiddleware({ env, fetch: fetchImpl });
    const cookie = await sessionCookie(5 * 60 * 1000);
    const res = await mw(new Request('https://app.test/dashboard', { headers: { cookie } }), pass);
    expect(res.status).toBe(200); // это результат next(), не собственный ответ модуля
    expect(setCookies(res)).toEqual([]); // cookie не переставляется
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('access истекает (<120с) -> refresh, перезапечатывает cookie на ответе next()', async () => {
    const fetchImpl = (async () =>
      Response.json({
        access_token: fakeJwt({ sub: 'u1', roles: ['x'] }),
        id_token: fakeJwt({ sub: 'u1' }),
        refresh_token: 'r2',
        token_type: 'Bearer',
        expires_in: 900,
      })) as typeof fetch;
    const mw = createAuthMiddleware({ env, fetch: fetchImpl });
    const cookie = await sessionCookie(60 * 1000); // <120с
    const res = await mw(new Request('https://app.test/dashboard', { headers: { cookie } }), pass);
    const set = setCookies(res).find((c) => c.startsWith(`${SESSION_COOKIE}=`))!;
    const sealed = parseCookies(set.split(';')[0]!)[SESSION_COOKIE]!;
    const data = await unseal<{ refreshToken: string }>(sealed, SECRET);
    expect(data!.refreshToken).toBe('r2');
  });

  it('одновременные refresh одного токена склеиваются в один запрос', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      await new Promise((r) => setTimeout(r, 10));
      return Response.json({
        access_token: fakeJwt({ sub: 'u1' }),
        id_token: fakeJwt({ sub: 'u1' }),
        refresh_token: 'r2',
        token_type: 'Bearer',
        expires_in: 900,
      });
    }) as typeof fetch;
    const mw = createAuthMiddleware({ env, fetch: fetchImpl });
    const cookie = await sessionCookie(60 * 1000, 'shared-token');
    await Promise.all([
      mw(new Request('https://app.test/a', { headers: { cookie } }), pass),
      mw(new Request('https://app.test/b', { headers: { cookie } }), pass),
      mw(new Request('https://app.test/c', { headers: { cookie } }), pass),
    ]);
    expect(calls).toBe(1); // дедуп по токену
  });

  it('refresh провалился на protect-пути -> редирект на login с next, cookie не стирается (T14)', async () => {
    const fetchImpl = (async () => Response.json({ error: 'invalid_grant' }, { status: 400 })) as typeof fetch;
    const mw = createAuthMiddleware({ env, fetch: fetchImpl, protect: ['/dashboard'] });
    const cookie = await sessionCookie(60 * 1000);
    const res = await mw(new Request('https://app.test/dashboard/x', { headers: { cookie } }), pass);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get('location')!);
    expect(loc.pathname).toBe('/api/auth/login');
    expect(loc.searchParams.get('next')).toBe('/dashboard/x');
    expect(setCookies(res).find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBeUndefined();
  });

  it('refresh провалился на НЕ-protect пути -> проходит анонимно (next), cookie не стирается (T14)', async () => {
    const fetchImpl = (async () => Response.json({ error: 'invalid_grant' }, { status: 400 })) as typeof fetch;
    const mw = createAuthMiddleware({ env, fetch: fetchImpl, protect: ['/dashboard'] });
    const cookie = await sessionCookie(60 * 1000);
    const res = await mw(new Request('https://app.test/public', { headers: { cookie } }), pass);
    expect(res.status).toBe(200);
    expect(setCookies(res).find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBeUndefined();
  });

  it('временный сбой refresh на публичной SSR-странице: cookie не вырезается, тихий вход не запускается', async () => {
    const fetchImpl = (async () => Response.json({ error: 'server_error' }, { status: 503 })) as typeof fetch;
    const mw = createAuthMiddleware({ env, fetch: fetchImpl, protect: ['/dashboard'] });
    const cookie = await sessionCookie(-1000);
    const res = await mw(new Request('https://app.test/public', { headers: { cookie } }),
      (headers) => { const r = new Response(null); r.headers.set('x-middleware-request-cookie', headers.get('cookie') ?? ''); r.headers.set('x-middleware-override-headers', 'cookie'); return r; });
    expect(setCookies(res)).toEqual([]);
    const forwarded = res.headers.get('x-middleware-request-cookie')!;
    expect(forwarded).toContain(cookie);
    expect(await getUser(forwarded, { env })).toBeNull();
    // Страница по образцу из README не уводит на /api/auth/login?silent=1.
    expect(silentCheckDone(forwarded, new URLSearchParams(), { env })).toBe(true);
  });

  it('нет сессии на protect-пути -> редирект на login', async () => {
    const mw = createAuthMiddleware({ env, fetch: (async () => new Response('')) as typeof fetch, protect: ['/dashboard'] });
    const res = await mw(new Request('https://app.test/dashboard'), pass);
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get('location')!).pathname).toBe('/api/auth/login');
  });

  it('нет сессии на публичном пути -> проходит (ответ next)', async () => {
    const mw = createAuthMiddleware({ env, fetch: (async () => new Response('')) as typeof fetch });
    const res = await mw(new Request('https://app.test/public'), pass);
    expect(res.status).toBe(200);
  });

  describe('запросы данных (fetch) не уводим на вход', () => {
    const mwNoSession = () =>
      createAuthMiddleware({ env, fetch: (async () => new Response('')) as typeof fetch, protect: ['/dashboard'] });

    it('нет сессии, fetch (Sec-Fetch-Mode: cors) на protect-пути -> 401 JSON без редиректа', async () => {
      const res = await mwNoSession()(
        new Request('https://app.test/dashboard/data', { headers: { 'sec-fetch-mode': 'cors' } }),
        pass,
      );
      expect(res.status).toBe(401);
      expect(res.headers.get('location')).toBeNull();
      expect(await res.json()).toEqual({ error: 'unauthenticated' });
    });

    it('нет сессии, старый браузер без Sec-Fetch, Accept: application/json -> 401', async () => {
      const res = await mwNoSession()(
        new Request('https://app.test/dashboard/data', { headers: { accept: 'application/json' } }),
        pass,
      );
      expect(res.status).toBe(401);
    });

    it('нет сессии, без Sec-Fetch-Mode и Accept: */* (curl) -> редирект, как раньше', async () => {
      const res = await mwNoSession()(
        new Request('https://app.test/dashboard', { headers: { accept: '*/*' } }),
        pass,
      );
      expect(res.status).toBe(302);
      expect(res.headers.get('vary')).toBe('Sec-Fetch-Mode, Accept');
    });

    it('ответ 401 тоже помечен Vary', async () => {
      const res = await mwNoSession()(
        new Request('https://app.test/dashboard', { headers: { 'sec-fetch-mode': 'cors' } }),
        pass,
      );
      expect(res.headers.get('vary')).toBe('Sec-Fetch-Mode, Accept');
    });

    it('next в редиректе на вход сохраняет query', async () => {
      const res = await mwNoSession()(new Request('https://app.test/dashboard/x?tab=2&q=a'), pass);
      expect(new URL(res.headers.get('location')!).searchParams.get('next')).toBe('/dashboard/x?tab=2&q=a');
    });

    it('маршруты модуля /api/auth/* не защищаются даже при protect: ["/"]', async () => {
      const mw = createAuthMiddleware({ env, fetch: (async () => new Response('')) as typeof fetch, protect: ['/'] });
      const res = await mw(new Request('https://app.test/api/auth/login?next=/'), pass);
      expect(res.status).toBe(200);
    });

    // Matcher из README ловит и /api/auth/*. Cookie, которую middleware
    // дописывает к next(), Next.js кладёт в ответ маршрута выхода — после его
    // стирания. Обновлять сессию здесь нельзя.
    it('logout при токене, истекающем меньше чем через 2 минуты -> middleware не обновляет сессию', async () => {
      const fetchImpl = vi.fn(async () =>
        Response.json({
          access_token: fakeJwt({ sub: 'u1' }),
          id_token: fakeJwt({ sub: 'u1' }),
          refresh_token: 'r2',
          token_type: 'Bearer',
          expires_in: 900,
        }),
      ) as unknown as typeof fetch;
      const mw = createAuthMiddleware({ env, fetch: fetchImpl, protect: ['/'] });
      const cookie = await sessionCookie(60 * 1000);
      const res = await mw(new Request('https://app.test/api/auth/logout', { headers: { cookie } }), pass);
      expect(res.status).toBe(200);
      expect(setCookies(res)).toEqual([]);
      expect(fetchImpl).not.toHaveBeenCalled();
    });

    it('нет сессии, переход по странице (Sec-Fetch-Mode: navigate) -> редирект на login', async () => {
      const res = await mwNoSession()(
        new Request('https://app.test/dashboard', {
          headers: { 'sec-fetch-mode': 'navigate', accept: 'text/html' },
        }),
        pass,
      );
      expect(res.status).toBe(302);
      expect(new URL(res.headers.get('location')!).pathname).toBe('/api/auth/login');
    });

    it('refresh провалился, fetch на protect-пути -> 401, cookie не стирается (T14)', async () => {
      const fetchImpl = (async () => Response.json({ error: 'invalid_grant' }, { status: 400 })) as typeof fetch;
      const mw = createAuthMiddleware({ env, fetch: fetchImpl, protect: ['/dashboard'] });
      const cookie = await sessionCookie(60 * 1000);
      const res = await mw(
        new Request('https://app.test/dashboard/data', { headers: { cookie, 'sec-fetch-mode': 'cors' } }),
        pass,
      );
      expect(res.status).toBe(401);
      expect(setCookies(res).find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBeUndefined();
    });
  });
});
