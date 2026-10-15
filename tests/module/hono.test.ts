import { confirmLogout, cookieNamesFor } from './helpers.js';
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { createHonoAuth } from '../../module/server/hono.js';
import { seal } from '../../module/server/core/cookie-seal.js';

// Адаптер Hono на настоящем приложении Hono: маршруты входа, защита и
// пользователь в обработчике.

const APP = 'https://app.test';
const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1';
const env = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: APP, AUTH_COOKIE_SECRET: SECRET };
const { session: SESSION_COOKIE, flow: FLOW_COOKIE } = cookieNamesFor(env);

function fakeJwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(unescape(encodeURIComponent(JSON.stringify(o))))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${b64({ alg: 'RS256' })}.${b64(payload)}.sig`;
}
function setCookies(res: Response): string[] {
  return (res.headers as unknown as { getSetCookie(): string[] }).getSetCookie();
}
// Выход помечает refresh-токен закрытым на весь процесс, поэтому у каждой
// сессии свой токен, как в жизни.
let sessionSequence = 0;
async function sessionCookie(expiresInMs: number) {
  const data = {
    user: { id: 'u1', name: 'Старое имя', roles: [] },
    accessToken: fakeJwt({ sub: 'u1' }),
    refreshToken: `r1-${++sessionSequence}`,
    accessTokenExpiresAt: Date.now() + expiresInMs,
  };
  return `${SESSION_COOKIE}=${await seal(data, SECRET)}`;
}
const noNetwork = (async () => {
  throw new Error('сеть не нужна');
}) as typeof fetch;
const refreshOk = (async () =>
  Response.json({
    access_token: fakeJwt({ sub: 'u1' }),
    id_token: fakeJwt({ sub: 'u1', name: 'Новое имя' }),
    refresh_token: 'r2',
    token_type: 'Bearer',
    expires_in: 900,
  })) as typeof fetch;
const refreshFails = (async () => Response.json({ error: 'invalid_grant' }, { status: 400 })) as typeof fetch;

const fetchMode = { 'sec-fetch-mode': 'cors' };
const navigation = { 'sec-fetch-mode': 'navigate', accept: 'text/html' };

function buildApp(fetchImpl: typeof fetch, protect: string[] = ['/app', '/api/notes']) {
  const auth = createHonoAuth({ env, fetch: fetchImpl, protect });
  const app = new Hono();
  app.use(auth.guard);
  app.on(['GET', 'POST'], '/api/auth/*', auth.routes);
  app.get('/api/notes', async (c) => c.json({ user: await auth.user(c) }));
  app.get('/api/public', async (c) => {
    c.header('set-cookie', 'theme=dark; Path=/', { append: true });
    return c.json({ user: await auth.user(c) });
  });
  // Обработчик, который возвращает голый Response, а не c.json().
  app.get('/raw', async () => new Response('raw'));
  app.get('/app', (c) => c.html('<h1>Кабинет</h1>'));
  return app;
}

describe('createHonoAuth: маршруты входа', () => {
  it('/api/auth/login -> редирект на /authorize сервиса и auth_flow', async () => {
    const res = await buildApp(noNetwork).request(`${APP}/api/auth/login?next=/app`);
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get('location')!).origin + '/authorize').toBe('https://auth.test/authorize');
    expect(setCookies(res).some((c) => c.startsWith(`${FLOW_COOKIE}.`))).toBe(true);
  });

  it('/api/auth/me без сессии -> 401', async () => {
    const res = await buildApp(noNetwork).request(`${APP}/api/auth/me`, { headers: fetchMode });
    expect(res.status).toBe(401);
  });
});

describe('createHonoAuth: методы маршрутов входа', () => {
  // Маршруты входа работают только по GET. Иначе POST (через app.all) или
  // HEAD (Hono шлёт его в app.get) тихо выполнили бы вход или выход.
  it('POST на маршрут входа -> 405 с Allow: GET, на сервис не ходим', async () => {
    let calls = 0;
    const counting = (async () => {
      calls++;
      return new Response('');
    }) as typeof fetch;
    const auth = createHonoAuth({ env, fetch: counting });
    const app = new Hono();
    app.all('/api/auth/*', auth.routes);
    const cookie = await sessionCookie(5 * 60 * 1000);
    const res = await app.request(`${APP}/api/auth/login`, { method: 'POST', headers: { cookie } });
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('GET');
    expect(setCookies(res)).toEqual([]);
    expect(calls).toBe(0);
  });

  it('HEAD на выход -> 405, сессия не стёрта и не отозвана', async () => {
    let calls = 0;
    const counting = (async () => {
      calls++;
      return new Response('');
    }) as typeof fetch;
    const auth = createHonoAuth({ env, fetch: counting });
    const app = new Hono();
    app.on(['GET', 'POST'], '/api/auth/*', auth.routes);
    const cookie = await sessionCookie(5 * 60 * 1000);
    const res = await app.request(`${APP}/api/auth/logout`, { method: 'HEAD', headers: { cookie } });
    expect(res.status).toBe(405);
    expect(setCookies(res)).toEqual([]);
    expect(calls).toBe(0);
  });
});

describe('createHonoAuth: выход', () => {
  // Защита не должна обновлять сессию на маршрутах входа: иначе после
  // стирания cookie выходом к ответу дописалась бы свежая — и человек остался
  // бы вошедшим.
  it('logout при токене, истекающем меньше чем через 2 минуты -> в ответе нет живой auth_session', async () => {
    const cookie = await sessionCookie(60 * 1000);
    const app = buildApp(refreshOk);
    const res = await confirmLogout((req) => app.request(req), APP, cookie);
    expect(res.status).toBe(302);
    const sessions = setCookies(res).filter((c) => c.startsWith(`${SESSION_COOKIE}=`));
    expect(sessions.length).toBeGreaterThan(0);
    for (const c of sessions) expect(c).toContain('Max-Age=0');
  });
});

describe('createHonoAuth: защита', () => {
  it('нет сессии, запрос данных к защищённому API -> 401, обработчик не вызван', async () => {
    const res = await buildApp(noNetwork).request(`${APP}/api/notes`, { headers: fetchMode });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthenticated' });
  });

  it('нет сессии, переход на защищённую страницу -> редирект на вход с next', async () => {
    const res = await buildApp(noNetwork).request(`${APP}/app?tab=1`, { headers: navigation });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get('location')!);
    expect(location.pathname).toBe('/api/auth/login');
    expect(location.searchParams.get('next')).toBe('/app?tab=1');
  });

  it('свежая сессия -> обработчик видит пользователя, cookie не переставляется', async () => {
    const cookie = await sessionCookie(5 * 60 * 1000);
    const res = await buildApp(noNetwork).request(`${APP}/api/notes`, { headers: { ...fetchMode, cookie } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: { id: 'u1', name: 'Старое имя', roles: [] } });
    expect(setCookies(res)).toEqual([]);
  });

  it('токен истекает -> обработчик видит обновлённого пользователя, ответ несёт новую cookie и свои cookie', async () => {
    const cookie = await sessionCookie(60 * 1000);
    const res = await buildApp(refreshOk).request(`${APP}/api/public`, { headers: { ...fetchMode, cookie } });
    expect((await res.json()).user.name).toBe('Новое имя');
    const cookies = setCookies(res);
    expect(cookies.some((c) => c.startsWith('theme=dark'))).toBe(true);
    const session = cookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
    expect(session).toBeDefined();
    expect(session).not.toContain('Max-Age=0');
  });

  it('обновление не удалось на открытом пути -> аноним и стёртая cookie', async () => {
    const cookie = await sessionCookie(60 * 1000);
    const res = await buildApp(refreshFails).request(`${APP}/api/public`, { headers: { ...fetchMode, cookie } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: null });
    expect(setCookies(res).find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toContain('Max-Age=0');
  });

  it('обработчик вернул голый Response -> обновлённая cookie всё равно дописана', async () => {
    const cookie = await sessionCookie(60 * 1000);
    const res = await buildApp(refreshOk).request(`${APP}/raw`, { headers: { cookie } });
    expect(await res.text()).toBe('raw');
    expect(setCookies(res).some((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBe(true);
  });

  it('user(c) без подключённой защиты читает пользователя из cookie', async () => {
    const auth = createHonoAuth({ env, fetch: noNetwork });
    const app = new Hono();
    app.get('/who', async (c) => c.json({ user: await auth.user(c) }));
    const cookie = await sessionCookie(5 * 60 * 1000);
    const res = await app.request(`${APP}/who`, { headers: { cookie } });
    expect((await res.json()).user.id).toBe('u1');
  });

  it('подходит приложению Hono со своими типами переменных', () => {
    const auth = createHonoAuth({ env, fetch: noNetwork });
    const app = new Hono<{ Variables: { requestId: string } }>();
    app.use(auth.guard);
    app.on(['GET', 'POST'], '/api/auth/*', auth.routes);
    app.get('/x', async (c) => c.json({ user: await auth.user(c), id: c.get('requestId') }));
    expect(app).toBeDefined();
  });
});
