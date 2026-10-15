import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { createAuthHandlers } from '../../module/server/handlers.js';
import { createHonoAuth } from '../../module/server/hono.js';
import { createAuthMiddleware } from '../../module/server/nextjs.js';
import { getUser } from '../../module/server/server.js';
import { seal } from '../../module/server/core/cookie-seal.js';
import { confirmLogout, cookieNamesFor } from './helpers.js';

// Запоздавший ответ refresh не должен вернуть cookie после выхода и не должен
// перезаписать сессию пользователя, вошедшего тем временем.
const APP = 'https://app.test';
const SECRET = 'test-only-cookie-secret-at-least-32-characters';
const env = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: APP, AUTH_COOKIE_SECRET: SECRET };
const names = cookieNamesFor(env);
const jwt = (sub: string) => `e30.${Buffer.from(JSON.stringify({ sub, roles: [] })).toString('base64url')}.sig`;
const tokens = (sub: string, refresh = `${sub}-next`) => Response.json({
  access_token: jwt(sub), id_token: jwt(sub), refresh_token: refresh, token_type: 'Bearer', expires_in: 900,
});
const req = (path: string, cookie = '') => new Request(APP + path, { headers: { cookie } });
const pair = (line: string) => line.split(';')[0]!;
const sessionOf = (res: Response) => res.headers.getSetCookie().find((c) => c.startsWith(`${names.session}=`));

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

// Пометка закрытых токенов общая на процесс, поэтому у каждого теста свой токен.
let sequence = 0;

// Сервис, у которого refresh можно задержать; запоминает все запросы.
function slowAuth() {
  const token = `A-refresh-${++sequence}`;
  const started = deferred();
  const gate = deferred();
  const revoked: string[] = [];
  const fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body ?? '{}'));
    if (String(url).endsWith('/oauth/revoke')) { revoked.push(body.token); return new Response(null); }
    if (body.grant_type === 'refresh_token') {
      if (revoked.includes(body.refresh_token)) return Response.json({ error: 'invalid_grant' }, { status: 400 });
      started.resolve();
      await gate.promise;
      return tokens('A');
    }
    return tokens('B', 'B-refresh');
  }) as typeof globalThis.fetch;
  return { fetch, started, gate, revoked, token };
}

async function expiredSessionA(auth: { token: string }) {
  return `${names.session}=${await seal({ user: { id: 'A', roles: [] }, accessToken: jwt('A'),
    refreshToken: auth.token, accessTokenExpiresAt: Date.now() - 1 }, SECRET)}`;
}

// Next.js: middleware и route handlers создаются отдельно, без общего аргумента.
function nextApp(fetch: typeof globalThis.fetch) {
  const middleware = createAuthMiddleware({ env, fetch });
  const handlers = createAuthHandlers({ env, fetch });
  const pass = (headers: Headers) => {
    const res = new Response(null);
    res.headers.set('x-middleware-override-headers', 'cookie');
    res.headers.set('x-middleware-request-cookie', headers.get('cookie') ?? '');
    return res;
  };
  return {
    page: (cookie: string) => middleware(req('/page', cookie), pass),
    send: (r: Request) => (r.method === 'POST' ? handlers.POST(r) : handlers.GET(r)),
    GET: handlers.GET,
  };
}

async function loginB(GET: (r: Request) => Promise<Response>, cookie: string) {
  const login = await GET(req('/api/auth/login?silent=0', cookie));
  const state = new URL(login.headers.get('location')!).searchParams.get('state')!;
  return GET(req(`/api/auth/callback?code=B&state=${encodeURIComponent(state)}`, `${cookie}; ${pair(login.headers.getSetCookie()[0]!)}`));
}

describe('запоздавший refresh', () => {
  it('после logout не возвращает cookie сессии', async () => {
    const auth = slowAuth();
    const h = createAuthHandlers({ env, fetch: auth.fetch });
    const old = await expiredSessionA(auth);
    const pending = h.GET(req('/api/auth/me', old));
    await auth.started.promise;
    const out = await confirmLogout((r) => (r.method === 'POST' ? h.POST(r) : h.GET(r)), APP, old);
    expect(out.status).toBe(302);
    expect(auth.revoked).toEqual([auth.token]);
    auth.gate.resolve();
    const late = await pending;
    expect(late.headers.getSetCookie()).toEqual([]);
    expect(late.status).toBe(401);
  });

  it('после callback другого пользователя не перезаписывает его сессию; прежний refresh отозван', async () => {
    const auth = slowAuth();
    const h = createAuthHandlers({ env, fetch: auth.fetch });
    const old = await expiredSessionA(auth);
    const pending = h.GET(req('/api/auth/me', old));
    await auth.started.promise;
    const callback = await loginB(h.GET, old);
    expect((await getUser(pair(sessionOf(callback)!), { env }))?.id).toBe('B');
    expect(auth.revoked).toEqual([auth.token]);
    auth.gate.resolve();
    const late = await pending;
    expect(late.headers.getSetCookie()).toEqual([]);
  });

  it('запрос со старой cookie после callback не стирает cookie нового пользователя', async () => {
    const auth = slowAuth();
    auth.gate.resolve();
    const h = createAuthHandlers({ env, fetch: auth.fetch });
    const old = await expiredSessionA(auth);
    await loginB(h.GET, old);
    const late = await h.GET(req('/api/auth/me', old));
    expect(late.status).toBe(401);
    expect(late.headers.getSetCookie()).toEqual([]);
  });

  it('Hono: guard и маршруты одного createHonoAuth видят выход друг друга', async () => {
    const auth = slowAuth();
    const hono = createHonoAuth({ env, fetch: auth.fetch });
    const app = new Hono();
    app.use(hono.guard);
    app.on(['GET', 'POST'], '/api/auth/*', hono.routes);
    app.get('/page', (c) => c.text('ok'));
    const old = await expiredSessionA(auth);
    const pending = app.request(req('/page', old));
    await auth.started.promise;
    await confirmLogout((r) => app.request(r), APP, old);
    auth.gate.resolve();
    const late = await pending;
    expect(late.status).toBe(200);
    expect(late.headers.getSetCookie()).toEqual([]);
  });

  it('Next.js: запоздавший refresh из middleware после logout в route handler не возвращает cookie', async () => {
    const auth = slowAuth();
    const app = nextApp(auth.fetch);
    const old = await expiredSessionA(auth);
    const pending = app.page(old);
    await auth.started.promise;
    await confirmLogout(app.send, APP, old);
    auth.gate.resolve();
    const late = await pending;
    expect(late.headers.getSetCookie()).toEqual([]);
    expect(late.headers.get('x-middleware-request-cookie')).not.toContain(names.session);
  });

  it('Next.js: запоздавший refresh из middleware после callback не перезаписывает новую сессию', async () => {
    const auth = slowAuth();
    const app = nextApp(auth.fetch);
    const old = await expiredSessionA(auth);
    const pending = app.page(old);
    await auth.started.promise;
    const callback = await loginB(app.GET, old);
    expect((await getUser(pair(sessionOf(callback)!), { env }))?.id).toBe('B');
    auth.gate.resolve();
    expect((await pending).headers.getSetCookie()).toEqual([]);
  });
});
