import { confirmLogout } from '../helpers.js';
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import type { FastifyInstance } from 'fastify';
import { makeAppFetch } from './inject-fetch.js';
import { createHonoAuth } from '../../../module/server/hono.js';
import { SESSION_COOKIE, FLOW_COOKIE } from '../../../module/server/cookies.js';
import { extractChallenge } from '../../adapters/http/helpers.js';

// Приложение Hono с адаптером против живого сервиса в процессе: обычный вход,
// «кто я», защищённый API, выход и тихий вход при живой SSO-сессии.

const APP = 'https://app.test';
const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1';
const env = { AUTH_URL: 'https://auth.example', AUTH_APP_URL: APP, AUTH_COOKIE_SECRET: SECRET };
const fetchMode = { 'sec-fetch-mode': 'cors' };

function setCookies(res: Response): string[] {
  return (res.headers as unknown as { getSetCookie(): string[] }).getSetCookie();
}
function pick(cookies: string[], name: string): string {
  const c = cookies.find((x) => x.startsWith(`${name}=`) || (name === FLOW_COOKIE && x.startsWith(`${name}.`)));
  if (!c) throw new Error(`нет cookie ${name}`);
  return c.split(';')[0]!;
}
function serviceCookie(res: { headers: Record<string, unknown> }, name: string): string {
  const raw = res.headers['set-cookie'];
  const lines = Array.isArray(raw) ? raw.map(String) : [String(raw ?? '')];
  const line = lines.find((l) => l.startsWith(`${name}=`));
  if (!line) throw new Error(`нет cookie ${name} от сервиса`);
  return line.split(';')[0]!;
}

// Форма входа сервиса по коду из почты. Возвращает адрес callback и SSO-cookie.
async function loginOnService(service: FastifyInstance, authorizeUrl: URL) {
  const form: Record<string, string> = {
    client_id: authorizeUrl.searchParams.get('client_id')!,
    redirect_uri: authorizeUrl.searchParams.get('redirect_uri')!,
    code_challenge: authorizeUrl.searchParams.get('code_challenge')!,
    code_challenge_method: 'S256',
    scope: authorizeUrl.searchParams.get('scope')!,
    state: authorizeUrl.searchParams.get('state')!,
    csrf: 'csrf-tok',
  };
  const headers = { 'content-type': 'application/x-www-form-urlencoded', cookie: 'csrf=csrf-tok' };
  const identifyRes = await service.inject({
    method: 'POST',
    url: '/authorize/identify',
    payload: new URLSearchParams({ ...form, email: 'user@x.com' }).toString(),
    headers,
  });
  const verify = await service.inject({
    method: 'POST',
    url: '/authorize/code/verify',
    payload: new URLSearchParams({ ...form, challenge: extractChallenge(identifyRes.body), code: 'CODE55' }).toString(),
    headers,
  });
  return { callback: new URL(verify.headers['location'] as string), sso: serviceCookie(verify, 'sso') };
}

function buildApp(fetchImpl: typeof fetch) {
  const auth = createHonoAuth({ env, fetch: fetchImpl, protect: ['/api/notes'] });
  const app = new Hono();
  app.use(auth.guard);
  app.on(['GET', 'POST'], '/api/auth/*', auth.routes);
  app.get('/api/notes', async (c) => c.json({ owner: (await auth.user(c))?.email }));
  return app;
}

describe('E2E: Hono-адаптер против живого сервиса', () => {
  it('вход -> «кто я» -> защищённый API -> выход -> тихий вход по SSO-сессии', async () => {
    const { fetch: serviceFetch, app: service } = await makeAppFetch(APP);
    const app = buildApp(serviceFetch);

    // Без входа защищённый API отвечает 401.
    expect((await app.request(`${APP}/api/notes`, { headers: fetchMode })).status).toBe(401);

    // Обычный вход (silent=0): форма сервиса -> callback приложения.
    const login = await app.request(`${APP}/api/auth/login?silent=0&next=/notes`);
    const authorizeUrl = new URL(login.headers.get('location')!);
    const flow = pick(setCookies(login), FLOW_COOKIE);
    const { callback, sso } = await loginOnService(service, authorizeUrl);
    const cb = await app.request(`${APP}/api/auth/callback${callback.search}`, { headers: { cookie: flow } });
    expect(new URL(cb.headers.get('location')!).pathname).toBe('/notes');
    const session = pick(setCookies(cb), SESSION_COOKIE);

    // «Кто я» и защищённый API видят пользователя.
    const me = await app.request(`${APP}/api/auth/me`, { headers: { ...fetchMode, cookie: session } });
    expect((await me.json()).user.email).toBe('user@x.com');
    const notes = await app.request(`${APP}/api/notes`, { headers: { ...fetchMode, cookie: session } });
    expect(await notes.json()).toEqual({ owner: 'user@x.com' });

    // Выход: cookie стёрта, редирект на /logout сервиса.
    const logout = await confirmLogout((req) => app.request(req), APP, session);
    expect(new URL(logout.headers.get('location')!).pathname).toBe('/logout');
    expect(setCookies(logout).find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toContain('Max-Age=0');

    // Тихий вход: в приложении cookie нет, а SSO-сессия сервиса жива (как
    // после входа в соседнее приложение) — сервис отдаёт код без формы.
    const silent = await app.request(`${APP}/api/auth/login?silent=1&next=/`);
    const silentUrl = new URL(silent.headers.get('location')!);
    expect(silentUrl.searchParams.get('prompt')).toBe('none');
    const authorize = await service.inject({
      method: 'GET',
      url: silentUrl.pathname + silentUrl.search,
      headers: { cookie: sso },
    });
    const silentCallback = new URL(authorize.headers['location'] as string);
    expect(silentCallback.searchParams.get('code')).toBeTruthy();
    const silentCb = await app.request(`${APP}/api/auth/callback${silentCallback.search}`, {
      headers: { cookie: pick(setCookies(silent), FLOW_COOKIE) },
    });
    expect(setCookies(silentCb).some((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBe(true);

    await service.close();
  });
});
