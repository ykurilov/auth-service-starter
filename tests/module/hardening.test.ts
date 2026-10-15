import { afterEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import { createAuthHandlers } from '../../module/server/handlers.js';
import { createSessionGuard } from '../../module/server/session-guard.js';
import { createHonoAuth } from '../../module/server/hono.js';
import { getUser, silentCheckDone } from '../../module/server/server.js';
import { seal, unseal } from '../../module/server/core/cookie-seal.js';
import { OidcClient } from '../../module/server/core/oidc-client.js';
import { loadModuleConfig } from '../../module/server/core/config.js';
import { computeChallenge } from '../../module/server/core/pkce.js';
import { FLOW_COOKIE, SESSION_COOKIE, LOGOUT_COOKIE, SILENT_CHECK_COOKIE, MAX_LOGIN_FLOWS } from '../../module/server/cookies.js';
import { confirmLogout } from './helpers.js';

const APP = 'https://app.test';
const SECRET = 'test-only-cookie-key-at-least-32-characters';
const env = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: APP, AUTH_COOKIE_SECRET: SECRET };
const jwt = (claims: object) => `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.signature`;
const tokenBody = () => ({ access_token: jwt({ sub: 'u1', roles: ['reader'] }),
  id_token: jwt({ sub: 'u1', name: 'Обновлённый' }), refresh_token: 'r2', token_type: 'Bearer', expires_in: 900 });
const ok = (async () => Response.json(tokenBody())) as typeof fetch;
async function session(ms: number, local = false) {
  return `${local ? 'auth_session' : SESSION_COOKIE}=${await seal({ user: { id: 'u1', name: 'Прежний', roles: [] },
    accessToken: jwt({ sub: 'u1' }), refreshToken: 'r1', accessTokenExpiresAt: Date.now() + ms }, SECRET)}`;
}
const req = (path: string, cookie = '') => new Request(`${APP}${path}`, { headers: { cookie, 'sec-fetch-mode': 'cors' } });
class Jar {
  values = new Map<string, string>();
  header() { return [...this.values].map(([k, v]) => `${k}=${v}`).join('; '); }
  take(res: Response) {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(';'); const idx = pair!.indexOf('=');
      const key = pair!.slice(0, idx);
      if (line.includes('Max-Age=0')) this.values.delete(key);
      else this.values.set(key, pair!.slice(idx + 1));
    }
  }
}
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

describe('refresh: временная ошибка сохраняет cookie и не подменяет её отзывом', () => {
  const failures: [string, typeof fetch][] = [
    ['network', async () => { throw new TypeError('offline'); }],
    ['500', async () => Response.json({ error: 'invalid_grant' }, { status: 500 })],
    ['429', async () => Response.json({ error: 'too_many_requests' }, { status: 429 })],
    ['malformed 400', async () => new Response('bad gateway', { status: 400 })],
    ['malformed 200', async () => Response.json({})],
  ];
  it.each(failures)('%s: действующий access проходит, истёкший получает 503 без стирания', async (_, fetch) => {
    const guard = createSessionGuard({ env, fetch, protect: ['/private'] });
    const valid = await guard(req('/private', await session(60_000)));
    expect(valid).toMatchObject({ kind: 'pass', user: { id: 'u1' }, setCookies: [] });
    const stale = await session(-1);
    const denied = await guard(req('/private', stale));
    expect(denied.kind).toBe('deny');
    if (denied.kind !== 'deny') throw new Error('deny');
    expect(denied.response.status).toBe(503);
    expect(denied.response.headers.get('retry-after')).toBe('5');
    expect(denied.response.headers.getSetCookie()).toEqual([]);
    const publicResult = await guard(req('/public', stale));
    expect(publicResult).toEqual({ kind: 'pass', user: null, setCookies: [] });
    const handlers = createAuthHandlers({ env, fetch });
    const me = await handlers.GET(req('/api/auth/me', stale));
    expect(me.status).toBe(503);
    expect(me.headers.getSetCookie()).toEqual([]);
    expect((await handlers.GET(req('/api/auth/me', await session(60_000)))).status).toBe(200);
  });
  it('подтверждённый invalid_grant: /me без guard отвечает 401 и стирает cookie', async () => {
    const handlers = createAuthHandlers({ env, fetch: async () => Response.json({ error: 'invalid_grant' }, { status: 400 }) });
    const res = await handlers.GET(req('/api/auth/me', await session(-1)));
    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie().join()).toContain(`${SESSION_COOKIE}=;`);
    expect(res.headers.getSetCookie().join()).toContain('Max-Age=0');
  });
  it('/me обновляет истёкший access, возвращает нового пользователя и пригодную cookie', async () => {
    const handlers = createAuthHandlers({ env, fetch: ok });
    const stale = await session(-1);
    expect(await getUser(stale, { env })).toBeNull();
    const me = await handlers.GET(req('/api/auth/me', stale));
    expect(me.status).toBe(200);
    expect((await me.json()).user.name).toBe('Обновлённый');
    const fresh = me.headers.getSetCookie()[0]!.split(';')[0]!;
    expect((await getUser(fresh, { env }))?.name).toBe('Обновлённый');
  });
  it.each([true, false])('Hono: самостоятельный /me, guard=%s', async (guarded) => {
    const auth = createHonoAuth({ env, fetch: ok });
    const app = new Hono();
    if (guarded) app.use(auth.guard);
    app.on(['GET', 'POST'], '/api/auth/*', auth.routes);
    const res = await app.request(req('/api/auth/me', await session(-1)));
    expect(res.status).toBe(200);
    expect((await res.json()).user.name).toBe('Обновлённый');
    expect(res.headers.getSetCookie()[0]).toContain(`${SESSION_COOKIE}=`);
  });
  it('Hono: после refresh и отзыва обработчик видит результат guard в том же запросе', async () => {
    for (const revoked of [false, true]) {
      const auth = createHonoAuth({ env, fetch: revoked ? async () => Response.json({ error: 'invalid_grant' }, { status: 400 }) : ok });
      const app = new Hono(); app.use(auth.guard);
      app.get('/public', async (c) => c.json({ user: await auth.user(c) }));
      const res = await app.request(req('/public', await session(-1)));
      const body = await res.json();
      expect(body.user?.name ?? null).toBe(revoked ? null : 'Обновлённый');
      expect(res.headers.getSetCookie().join().includes('Max-Age=0')).toBe(revoked);
    }
  });
});

describe('сроки и область доверия cookie', () => {
  it('HTTPS не доверяет legacy session и silent mark', async () => {
    const legacy = await session(900_000, true);
    expect(await getUser(legacy, { env })).toBeNull();
    const fetch = vi.fn(ok);
    expect((await createAuthHandlers({ env, fetch }).GET(req('/api/auth/me', legacy))).status).toBe(401);
    expect(fetch).not.toHaveBeenCalled();
    expect(silentCheckDone('auth_silent_checked=1')).toBe(false);
  });
  it('HTTP localhost использует имена без __Host- и читает свою сессию', async () => {
    const localEnv = { ...env, AUTH_APP_URL: 'http://localhost:3000' };
    const cookie = await session(-1, true);
    const handlers = createAuthHandlers({ env: localEnv, fetch: ok });
    const res = await handlers.GET(new Request('http://localhost:3000/api/auth/me', { headers: { cookie } }));
    const line = res.headers.getSetCookie()[0]!;
    expect(line.startsWith('auth_session=')).toBe(true);
    expect(line).not.toContain('Secure');
    expect((await getUser(line.split(';')[0]!, { env: localEnv }))?.name).toBe('Обновлённый');
    expect(silentCheckDone('auth_silent_checked=1', undefined, { env: localEnv })).toBe(true);
  });
  it('сервер отвергает просроченный sealed session даже при действующем access', async () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-01T00:00:00Z'));
    const cookie = await session(40 * 24 * 3600_000);
    vi.setSystemTime(new Date('2026-11-01T00:00:00Z'));
    expect(await getUser(cookie, { env })).toBeNull();
    const fetch = vi.fn(ok);
    const res = await createAuthHandlers({ env, fetch }).GET(req('/api/auth/me', cookie));
    expect(res.status).toBe(401);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('независимые flow и PKCE', () => {
  it('два входа завершаются с собственными state/verifier/next; callback удаляет только свой flow', async () => {
    const challenges = new Map<string, string>();
    const fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(init!.body as string);
      expect(await computeChallenge(body.code_verifier)).toBe(challenges.get(body.code));
      return Response.json(tokenBody());
    });
    const handlers = createAuthHandlers({ env, fetch }); const jar = new Jar();
    const states: string[] = [];
    for (const id of ['A', 'B']) {
      const res = await handlers.GET(req(`/api/auth/login?silent=0&next=/${id}`, jar.header())); jar.take(res);
      const target = new URL(res.headers.get('location')!);
      states.push(target.searchParams.get('state')!);
      challenges.set(id, target.searchParams.get('code_challenge')!);
    }
    expect([...jar.values.keys()].filter((k) => k.startsWith(`${FLOW_COOKIE}.`))).toHaveLength(2);
    const forged = await handlers.GET(req(`/api/auth/callback?code=A&state=${states[0]}~forged`, jar.header()));
    expect(forged.status).toBe(400); expect(forged.headers.getSetCookie()).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
    for (const [index, id] of ['A', 'B'].entries()) {
      const res = await handlers.GET(req(`/api/auth/callback?code=${id}&state=${states[index]}`, jar.header()));
      expect(res.headers.get('location')).toBe(`${APP}/${id}`);
      const cleared = res.headers.getSetCookie().filter((c) => c.startsWith(`${FLOW_COOKIE}.`));
      expect(cleared).toHaveLength(1); expect(cleared[0]).toContain(states[index]); jar.take(res);
    }
    expect(fetch).toHaveBeenCalledTimes(2);
    expect([...jar.values.keys()].filter((k) => k.startsWith(`${FLOW_COOKIE}.`))).toHaveLength(0);
  });
  it('истёкший flow и state fallback не обменивают код; следующий login освобождает места', async () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-01T00:00:00Z'));
    const fetch = vi.fn(ok); const handlers = createAuthHandlers({ env, fetch }); const jar = new Jar();
    const first = await handlers.GET(req('/api/auth/login?silent=1&next=/public')); jar.take(first);
    const state = new URL(first.headers.get('location')!).searchParams.get('state');
    vi.setSystemTime(new Date('2026-10-01T00:10:01Z'));
    const callback = await handlers.GET(req(`/api/auth/callback?code=x&state=${state}`, jar.header()));
    expect(callback.status).toBe(400); expect(fetch).not.toHaveBeenCalled();
    const next = await handlers.GET(req('/api/auth/login?silent=0', jar.header())); jar.take(next);
    expect(next.status).toBe(302);
    expect([...jar.values.keys()].filter((k) => k.startsWith(`${FLOW_COOKIE}.`))).toHaveLength(1);
  });
  it('лимит активных flow не удаляет другие попытки', async () => {
    const handlers = createAuthHandlers({ env, fetch: ok }); const jar = new Jar();
    for (let i = 0; i < MAX_LOGIN_FLOWS; i++) jar.take(await handlers.GET(req('/api/auth/login?silent=0', jar.header())));
    const before = jar.header(); const extra = await handlers.GET(req('/api/auth/login?silent=0', before));
    expect(extra.status).toBe(429); expect(extra.headers.getSetCookie()).toEqual([]);
    const key = [...jar.values.keys()][0]!;
    const state = key.slice(FLOW_COOKIE.length + 1);
    const done = await handlers.GET(req(`/api/auth/callback?code=x&state=${state}`, jar.header())); jar.take(done);
    expect((await handlers.GET(req('/api/auth/login?silent=0', jar.header()))).status).toBe(302);
  });
});

describe('OIDC: ограниченное ожидание и строгий ответ', () => {
  it('deadline ограничивает зависший fetch и отдельно зависшее тело', async () => {
    for (const fetch of [async () => new Promise<Response>(() => {}),
      async () => new Response(new ReadableStream({ start() { /* тело не завершается */ } }))]) {
      const client = new OidcClient(loadModuleConfig({ env, fetch, timeoutMs: 15 }));
      await expect(client.refreshTokens('r1')).rejects.toMatchObject({ error: 'timeout' });
    }
  });
  it.each([{ expires_in: '900' }, { expires_in: 0 }, { expires_in: 1.5 }, { refresh_token: '' },
    { token_type: 'Basic' }, { access_token: null }, { id_token: 123 }])('отвергает %j', async (patch) => {
    const client = new OidcClient(loadModuleConfig({ env, fetch: async () => Response.json({ ...tokenBody(), ...patch }) }));
    await expect(client.refreshTokens('r1')).rejects.toMatchObject({ error: 'invalid_response' });
  });
});

describe('выход', () => {
  it('GET не отзывает и не очищает сессию; POST требует Origin и CSRF', async () => {
    const fetch = vi.fn(ok); const handlers = createAuthHandlers({ env, fetch });
    const cookie = await session(60_000);
    const page = await handlers.GET(req('/api/auth/logout', cookie));
    expect(page.status).toBe(200); expect(fetch).not.toHaveBeenCalled();
    expect(page.headers.getSetCookie().some((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBe(false);
    const csrf = (await page.text()).match(/name="csrf" value="([^"]+)"/)![1]!;
    const csrfCookie = page.headers.getSetCookie()[0]!.split(';')[0];
    for (const origin of ['https://evil.test', APP]) {
      const res = await handlers.POST(new Request(`${APP}/api/auth/logout`, { method: 'POST',
        headers: { cookie: `${cookie}; ${csrfCookie}`, origin }, body: new URLSearchParams({ csrf: origin === APP ? 'wrong' : csrf }) }));
      expect(res.status).toBe(403); expect(res.headers.getSetCookie()).toEqual([]);
    }
    const res = await confirmLogout((r) => r.method === 'POST' ? handlers.POST(r) : handlers.GET(r), APP, cookie);
    expect(res.status).toBe(302); expect(fetch).toHaveBeenCalledTimes(1);
    expect(res.headers.getSetCookie().join()).toContain(`${SESSION_COOKIE}=;`);
    expect(res.headers.getSetCookie().join()).toContain(`${LOGOUT_COOKIE}=;`);
  });
  it('зависший revoke не мешает подтверждённому локальному выходу', async () => {
    const handlers = createAuthHandlers({ env, timeoutMs: 15, fetch: async () => new Promise(() => {}) });
    const res = await confirmLogout((r) => r.method === 'POST' ? handlers.POST(r) : handlers.GET(r), APP, await session(60_000));
    expect(res.status).toBe(302);
    expect(res.headers.getSetCookie().join()).toContain('Max-Age=0');
  });
});
