import { describe, it, expect } from 'vitest';
import { createAuthHandlers } from '../../module/server/handlers.js';
import { getUser } from '../../module/server/server.js';
import { seal } from '../../module/server/core/cookie-seal.js';
import { authCookieNames } from '../../module/server/cookies.js';
import { cookieNamesFor } from './helpers.js';

// Браузер не разделяет cookie по портам: два приложения на одном hostname
// видят cookie друг друга. Имена несут суффикс client_id, и чужие cookie модуль
// не читает и не стирает.
const nextEnv = {
  AUTH_URL: 'http://localhost:3016', AUTH_APP_URL: 'http://localhost:3005',
  AUTH_COOKIE_SECRET: 'nextjs-demo-secret-longer-than-32-chars', AUTH_CLIENT_ID: 'nextjs-demo',
};
const honoEnv = {
  AUTH_URL: 'http://localhost:3016', AUTH_APP_URL: 'http://localhost:3007',
  AUTH_COOKIE_SECRET: 'hono-demo-secret-longer-than-32-characters', AUTH_CLIENT_ID: 'hono-vite-demo',
};
const httpsEnv = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: 'https://app.test', AUTH_COOKIE_SECRET: 'https-secret-longer-than-32-characters!!' };
const jwt = (sub: string) => `e30.${Buffer.from(JSON.stringify({ sub })).toString('base64url')}.sig`;
const noNetwork = (async () => { throw new Error('сеть не нужна'); }) as typeof fetch;

async function sessionPair(env: typeof nextEnv) {
  const sealed = await seal({ user: { id: env.AUTH_CLIENT_ID, roles: [] }, accessToken: jwt(env.AUTH_CLIENT_ID),
    refreshToken: `r-${env.AUTH_CLIENT_ID}`, accessTokenExpiresAt: Date.now() + 600_000 }, env.AUTH_COOKIE_SECRET);
  return `${cookieNamesFor(env).session}=${sealed}`;
}

describe('cookie двух приложений на одном hostname', () => {
  it('имена различаются суффиксом client_id', () => {
    const a = cookieNamesFor(nextEnv);
    const b = cookieNamesFor(honoEnv);
    expect(a.session).toBe('auth_session.nextjs-demo');
    expect(b.session).toBe('auth_session.hono-vite-demo');
    for (const key of ['session', 'flow', 'silentCheck', 'logout'] as const) expect(a[key]).not.toBe(b[key]);
  });

  it('HTTPS сохраняет префикс __Host-; по умолчанию суффикс — hostname', () => {
    const names = cookieNamesFor(httpsEnv);
    expect(names.session).toBe('__Host-auth_session.app.test');
    expect(names.flow).toBe('__Host-auth_flow.app.test');
    expect(names.silentCheck).toBe('__Host-auth_silent_checked.app.test');
    expect(names.logout).toBe('__Host-auth_logout.app.test');
  });

  it('client_id с недопустимыми для имени cookie символами даёт корректное и различимое имя', () => {
    const a = authCookieNames('мой клиент;1', 'https://app.test').session;
    const b = authCookieNames('мой клиент;2', 'https://app.test').session;
    expect(a).toMatch(/^__Host-auth_session\.[A-Za-z0-9._-]+$/);
    expect(a).not.toBe(b);
  });

  it('/me одного приложения не стирает сессию другого', async () => {
    const both = `${await sessionPair(nextEnv)}; ${await sessionPair(honoEnv)}`;
    const next = createAuthHandlers({ env: nextEnv, fetch: noNetwork });
    const hono = createAuthHandlers({ env: honoEnv, fetch: noNetwork });
    const resNext = await next.GET(new Request('http://localhost:3005/api/auth/me', { headers: { cookie: both } }));
    const resHono = await hono.GET(new Request('http://localhost:3007/api/auth/me', { headers: { cookie: both } }));
    expect((await resNext.json()).user.id).toBe('nextjs-demo');
    expect((await resHono.json()).user.id).toBe('hono-vite-demo');
    expect([...resNext.headers.getSetCookie(), ...resHono.headers.getSetCookie()]).toEqual([]);
  });

  it('сессия только соседнего приложения: 401 без Set-Cookie', async () => {
    const hono = createAuthHandlers({ env: honoEnv, fetch: noNetwork });
    const res = await hono.GET(new Request('http://localhost:3007/api/auth/me', { headers: { cookie: await sessionPair(nextEnv) } }));
    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(await getUser(await sessionPair(nextEnv), { env: honoEnv })).toBeNull();
  });

  it('незавершённые входы соседа не считаются в лимит и не стираются', async () => {
    const next = createAuthHandlers({ env: nextEnv, fetch: noNetwork });
    const hono = createAuthHandlers({ env: honoEnv, fetch: noNetwork });
    const foreign: string[] = [];
    for (let i = 0; i < 4; i++) {
      const res = await next.GET(new Request('http://localhost:3005/api/auth/login?silent=0&next=/', { headers: { cookie: foreign.join('; ') } }));
      foreign.push(res.headers.getSetCookie()[0]!.split(';')[0]!);
    }
    const res = await hono.GET(new Request('http://localhost:3007/api/auth/login?silent=0&next=/', { headers: { cookie: foreign.join('; ') } }));
    expect(res.status).toBe(302);
    const set = res.headers.getSetCookie();
    expect(set.filter((c) => c.includes('Max-Age=0'))).toEqual([]);
    expect(set.some((c) => c.startsWith(`${cookieNamesFor(honoEnv).flow}.`))).toBe(true);
  });

  it('flow с похожим client_id (a и a.b) не принимается за свой', async () => {
    const env = (id: string) => ({ ...httpsEnv, AUTH_CLIENT_ID: id, AUTH_COOKIE_SECRET: `${id}-secret-longer-than-32-characters!!` });
    const ab = createAuthHandlers({ env: env('a.b'), fetch: noNetwork });
    const a = createAuthHandlers({ env: env('a'), fetch: noNetwork });
    const started = await ab.GET(new Request('https://app.test/api/auth/login?silent=0&next=/'));
    const flow = started.headers.getSetCookie()[0]!.split(';')[0]!;
    const res = await a.GET(new Request('https://app.test/api/auth/login?silent=0&next=/', { headers: { cookie: flow } }));
    expect(res.headers.getSetCookie().filter((c) => c.includes('Max-Age=0'))).toEqual([]);
  });
});
