import { describe, it, expect, vi, afterEach } from 'vitest';
import { createAuthHandlers } from '../../module/server/handlers.js';
import { createSessionGuard } from '../../module/server/session-guard.js';
import { getUser } from '../../module/server/server.js';
import { seal } from '../../module/server/core/cookie-seal.js';
import { FLOW_MAX_AGE, MAX_LOGIN_FLOWS, SILENT_CHECK_PARAM } from '../../module/server/cookies.js';
import { cookieNamesFor } from './helpers.js';

// Находки третьего аудита модуля (T09–T27).
const APP = 'https://app.test';
const SECRET = 'test-only-cookie-secret-at-least-32-characters';
const env = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: APP, AUTH_COOKIE_SECRET: SECRET };
const names = cookieNamesFor(env);
const req = (path: string, cookie = '') => new Request(APP + path, { headers: { cookie } });
const pair = (line: string) => line.split(';')[0]!;
const bytes = (s: string) => new TextEncoder().encode(s).length;
const jwt = (payload: Record<string, unknown>) =>
  `e30.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.sig`;
const roleList = (count: number) => Array.from({ length: count }, (_, i) => `role-${String(i).padStart(4, '0')}-reader-x`);

// Пометка закрытых токенов общая на процесс: у каждого теста свои токены.
let sequence = 0;
const unique = (base: string) => `${base}-${++sequence}`;

interface Service { fetch: typeof fetch; calls: { refresh: number; revoked: string[] } }
// Сервис входа: обмен кода и refresh выдают токены sub с ролями; refresh можно сломать.
function service(opts: { roles?: string[]; refresh?: 'ok' | 'invalid_grant' | 'down'; refreshToken?: string } = {}): Service {
  const calls = { refresh: 0, revoked: [] as string[] };
  const refreshToken = opts.refreshToken ?? unique('R');
  const fetchImpl = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body ?? '{}'));
    if (String(url).endsWith('/oauth/revoke')) { calls.revoked.push(body.token); return new Response(null); }
    if (body.grant_type === 'refresh_token') {
      calls.refresh++;
      if (opts.refresh === 'invalid_grant') return Response.json({ error: 'invalid_grant' }, { status: 400 });
      if (opts.refresh === 'down') return Response.json({ error: 'server_error' }, { status: 503 });
    }
    return Response.json({
      access_token: jwt({ sub: 'U', roles: opts.roles ?? [] }), id_token: jwt({ sub: 'U', name: 'Юля' }),
      refresh_token: refreshToken, token_type: 'Bearer', expires_in: 900,
    });
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

// Браузерная банка cookie: применяет Set-Cookie так же, как браузер.
function jar(initial: string[] = []) {
  const store = new Map<string, string>();
  for (const p of initial) store.set(p.slice(0, p.indexOf('=')), p.slice(p.indexOf('=') + 1));
  return {
    take(res: Response) {
      for (const line of res.headers.getSetCookie()) {
        const p = pair(line);
        const name = p.slice(0, p.indexOf('='));
        if (/Max-Age=0(?:;|$)/.test(line)) store.delete(name);
        else store.set(name, p.slice(p.indexOf('=') + 1));
      }
      return res;
    },
    header: () => [...store].map(([k, v]) => `${k}=${v}`).join('; '),
    get: (name: string) => store.get(name),
    names: () => [...store.keys()],
  };
}

// Вход целиком: login -> (сервис) -> callback.
async function signIn(h: ReturnType<typeof createAuthHandlers>, query: string, browser = jar(), callbackQuery = 'code=c') {
  const login = browser.take(await h.GET(req(`/api/auth/login?${query}`, browser.header())));
  const state = new URL(login.headers.get('location')!).searchParams.get('state')!;
  const callback = browser.take(await h.GET(req(`/api/auth/callback?${callbackQuery}&state=${encodeURIComponent(state)}`, browser.header())));
  return { login, callback, browser };
}

const expiringSession = async (refreshToken: string, msLeft = 60_000) => `${names.session}=${await seal({
  user: { id: 'U', roles: [] }, accessToken: jwt({ sub: 'U' }), refreshToken, accessTokenExpiresAt: Date.now() + msLeft,
}, SECRET)}`;

afterEach(() => { vi.useRealTimers(); });

describe('T09: не-ASCII в next', () => {
  it('обычный вход на /кабинет выдаёт сессию и ведёт на закодированный путь', async () => {
    const h = createAuthHandlers({ env, fetch: service().fetch });
    const { callback, browser } = await signIn(h, `silent=0&next=${encodeURIComponent('/кабинет?вкладка=счета')}`);
    expect(callback.status).toBe(302);
    expect(callback.headers.get('location')).toBe(`${APP}/${encodeURIComponent('кабинет')}?${encodeURIComponent('вкладка')}=${encodeURIComponent('счета')}`);
    expect(browser.get(names.session)).toBeTruthy();
  });

  it('тихая проверка с ошибкой не даёт 500, а возвращает на страницу', async () => {
    const h = createAuthHandlers({ env, fetch: service().fetch });
    const { callback } = await signIn(h, `silent=1&next=${encodeURIComponent('/кабинет')}`, jar(), 'error=login_required');
    expect(callback.status).toBe(302);
    expect(callback.headers.get('location')).toBe(`${APP}/${encodeURIComponent('кабинет')}`);
  });

  it('ни один Location не содержит сырых символов', async () => {
    const h = createAuthHandlers({ env, fetch: service().fetch });
    for (const query of ['silent=1', 'silent=0', '']) {
      for (const cb of ['code=c', 'error=login_required', 'error=access_denied']) {
        const { login, callback } = await signIn(h, `${query}&next=${encodeURIComponent('/отчёт/№1?q=кот#раздел')}`, jar(), cb);
        for (const res of [login, callback]) {
          const location = res.headers.get('location');
          if (location) expect(location).toMatch(/^[\x21-\x7e]+$/);
        }
      }
    }
  });
});

describe('T10: размер cookie сессии', () => {
  it('роли не дублируются в cookie: 60 ролей помещаются, и роли читаются', async () => {
    const roles = roleList(60);
    const h = createAuthHandlers({ env, fetch: service({ roles }).fetch });
    const { callback, browser } = await signIn(h, 'silent=0&next=/');
    const line = callback.headers.getSetCookie().find((c) => c.startsWith(`${names.session}=`))!;
    expect(bytes(pair(line))).toBeLessThanOrEqual(4000);
    expect((await getUser(browser.header(), { env }))?.roles).toEqual(roles);
    const me = await h.GET(req('/api/auth/me', browser.header()));
    expect((await me.json()).user.roles).toEqual(roles);
  });

  it('слишком большая сессия: страница ошибки, без cookie сессии и без метки, токен отозван', async () => {
    for (const mode of ['silent=0', 'silent=1', '']) {
      const svc = service({ roles: roleList(400) });
      const h = createAuthHandlers({ env, fetch: svc.fetch });
      const { callback, browser } = await signIn(h, `${mode}&next=/x`);
      expect(callback.status).toBe(400);
      expect(callback.headers.get('location')).toBeNull();
      expect(await callback.text()).toContain('слишком');
      expect(browser.get(names.session)).toBeUndefined();
      expect(callback.headers.getSetCookie().some((c) => c.startsWith(`${names.silentCheck}=1`))).toBe(false);
      expect(browser.names().some((n) => n.startsWith(`${names.flow}.`))).toBe(false);
      expect(svc.calls.revoked).toHaveLength(1);
    }
  });

  it('refresh в слишком большую сессию не выдаёт cookie и не повторяется по кругу', async () => {
    const svc = service({ roles: roleList(400) });
    const h = createAuthHandlers({ env, fetch: svc.fetch });
    const cookie = await expiringSession(unique('R-old'), -1);
    for (let i = 0; i < 2; i++) {
      const me = await h.GET(req('/api/auth/me', cookie));
      expect(me.status).toBe(401);
      expect(me.headers.getSetCookie().filter((c) => c.startsWith(`${names.session}=`))).toEqual([]);
    }
    expect(svc.calls.refresh).toBe(1);
    expect(svc.calls.revoked).toHaveLength(1);
  });
});

describe('T13: срок попытки входа', () => {
  it('cookie попытки живёт не меньше часа: код из письма с продлениями успевает', async () => {
    expect(FLOW_MAX_AGE).toBeGreaterThanOrEqual(60 * 60);
    vi.useFakeTimers({ toFake: ['Date'] });
    const h = createAuthHandlers({ env, fetch: service().fetch });
    const browser = jar();
    const login = browser.take(await h.GET(req('/api/auth/login?silent=0&next=/a')));
    expect(login.headers.getSetCookie().find((c) => c.startsWith(`${names.flow}.`))).toContain(`Max-Age=${FLOW_MAX_AGE}`);
    vi.setSystemTime(Date.now() + 55 * 60_000);
    const state = new URL(login.headers.get('location')!).searchParams.get('state')!;
    const callback = await h.GET(req(`/api/auth/callback?code=c&state=${state}`, browser.header()));
    expect(callback.status).toBe(302);
    expect(callback.headers.get('location')).toBe(`${APP}/a`);
  });

  it('сверх лимита попыток новая вытесняет самую старую, а не отказывает', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const h = createAuthHandlers({ env });
    const browser = jar();
    const order: string[] = [];
    for (let i = 0; i < MAX_LOGIN_FLOWS; i++) {
      const before = new Set(browser.names());
      browser.take(await h.GET(req('/api/auth/login?silent=0&next=/', browser.header())));
      order.push(browser.names().find((n) => !before.has(n))!);
      vi.setSystemTime(Date.now() + 1000);
    }
    for (const silent of ['0', '1']) {
      const res = browser.take(await h.GET(req(`/api/auth/login?silent=${silent}&next=/`, browser.header())));
      expect(res.status).toBe(302);
      expect(new URL(res.headers.get('location')!).origin).toBe('https://auth.test');
      expect(browser.get(order.shift()!)).toBeUndefined();
      expect(browser.names().filter((n) => n.startsWith(`${names.flow}.`))).toHaveLength(MAX_LOGIN_FLOWS);
      vi.setSystemTime(Date.now() + 1000);
    }
  });
});

describe('T14: запоздавший запрос со старой cookie', () => {
  it('отказ refresh старой сессии не стирает новую сессию', async () => {
    const svc = service({ refresh: 'invalid_grant' });
    const h = createAuthHandlers({ env, fetch: svc.fetch });
    const guard = createSessionGuard({ env, fetch: svc.fetch, protect: ['/dashboard'] });
    const stale = await expiringSession(unique('R-stale'), -1);
    const { browser } = await signIn(h, 'silent=0&next=/');
    const fresh = browser.get(names.session);
    expect(fresh).toBeTruthy();
    // Запросы, отправленные браузером со старой cookie до входа, отвечают позже.
    browser.take(await h.GET(req('/api/auth/me', stale)));
    const decision = await guard(req('/dashboard', stale));
    if (decision.kind === 'deny') browser.take(decision.response);
    expect(browser.get(names.session)).toBe(fresh);
  });

  it('отозванный токен не спрашивается у сервиса на каждом запросе', async () => {
    const svc = service({ refresh: 'invalid_grant' });
    const h = createAuthHandlers({ env, fetch: svc.fetch });
    const stale = await expiringSession(unique('R-stale'), -1);
    for (let i = 0; i < 3; i++) expect((await h.GET(req('/api/auth/me', stale))).status).toBe(401);
    expect(svc.calls.refresh).toBe(1);
  });
});

describe('T15: метка тихой проверки и явный вход', () => {
  it('login без silent при метке всё равно сначала пробует тихо', async () => {
    const h = createAuthHandlers({ env });
    const res = await h.GET(req('/api/auth/login?next=/dashboard', `${names.silentCheck}=1`));
    expect(new URL(res.headers.get('location')!).searchParams.get('prompt')).toBe('none');
  });

  it('тихая попытка без SSO переходит к обычному входу, без круга', async () => {
    const h = createAuthHandlers({ env, fetch: service().fetch });
    const { callback } = await signIn(h, 'next=/dashboard', jar([`${names.silentCheck}=1`]), 'error=login_required');
    const location = new URL(callback.headers.get('location')!);
    expect(location.origin).toBe('https://auth.test');
    expect(location.searchParams.has('prompt')).toBe(false);
  });

  it('silent=1 при метке по-прежнему не ходит на сервис', async () => {
    const h = createAuthHandlers({ env });
    const res = await h.GET(req('/api/auth/login?silent=1&next=/', `${names.silentCheck}=1`));
    expect(res.headers.get('location')).toBe(`${APP}/`);
  });
});

describe('T26: сервис входа недоступен', () => {
  it('после сбоя refresh следующие запросы не ждут сервис, пока идёт пауза', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const svc = service({ refresh: 'down' });
    const h = createAuthHandlers({ env, fetch: svc.fetch });
    const valid = await expiringSession(unique('R-down'), 60_000);
    const expired = await expiringSession(unique('R-down'), -1);
    expect((await h.GET(req('/api/auth/me', valid))).status).toBe(200);
    expect(svc.calls.refresh).toBe(1);
    expect((await h.GET(req('/api/auth/me', valid))).status).toBe(200);
    expect((await h.GET(req('/api/auth/me', expired))).status).toBe(503);
    expect(svc.calls.refresh).toBe(1);
    vi.setSystemTime(Date.now() + 30_000);
    expect((await h.GET(req('/api/auth/me', expired))).status).toBe(503);
    expect(svc.calls.refresh).toBe(2);
  });

  it.each([
    ['сеть', async () => { throw new TypeError('offline'); }],
    ['timeout', async () => new Promise<Response>(() => {})],
    ['500', async () => Response.json({ error: 'server_error' }, { status: 500 })],
  ])('пауза включается при недоступности сервиса: %s', async (_, failure) => {
    let refreshes = 0;
    const fetchImpl = (async () => { refreshes++; return failure(); }) as typeof fetch;
    const h = createAuthHandlers({ env, fetch: fetchImpl, timeoutMs: 20 });
    expect((await h.GET(req('/api/auth/me', await expiringSession(unique('R-a'), -1)))).status).toBe(503);
    expect((await h.GET(req('/api/auth/me', await expiringSession(unique('R-b'), -1)))).status).toBe(503);
    expect(refreshes).toBe(1);
  });

  // Сервис работает, но отказал одной сессии: остальные пользователи не ждут.
  it.each([
    ['429', () => Response.json({ error: 'too_many_requests' }, { status: 429 })],
    ['чужой 400', () => Response.json({ error: 'invalid_client' }, { status: 400 })],
    ['некорректный ответ', () => Response.json({})],
    ['другой пользователь', () => Response.json({ access_token: jwt({ sub: 'X' }), id_token: jwt({ sub: 'X' }),
      refresh_token: unique('R-x'), token_type: 'Bearer', expires_in: 900 })],
  ])('сбой одной сессии (%s) не ставит паузу остальным', async (_, failure) => {
    const bad = unique('R-bad');
    let refreshes = 0;
    const fetchImpl = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      refreshes++;
      const body = JSON.parse(String(init?.body ?? '{}'));
      if (body.refresh_token === bad) return failure();
      return Response.json({ access_token: jwt({ sub: 'U' }), id_token: jwt({ sub: 'U' }),
        refresh_token: unique('R-ok'), token_type: 'Bearer', expires_in: 900 });
    }) as typeof fetch;
    const h = createAuthHandlers({ env, fetch: fetchImpl });
    expect((await h.GET(req('/api/auth/me', await expiringSession(bad, -1)))).status).toBe(503);
    expect((await h.GET(req('/api/auth/me', await expiringSession(unique('R-good'), -1)))).status).toBe(200);
    expect(refreshes).toBe(2);
  });
});

describe('T27: суммарный размер попыток входа', () => {
  const longNext = '/reports?q=' + 'x'.repeat(2000);

  it('четыре попытки с длинным next занимают в Cookie меньше 2 КБ', async () => {
    const h = createAuthHandlers({ env });
    const browser = jar();
    for (let i = 0; i < MAX_LOGIN_FLOWS; i++)
      browser.take(await h.GET(req(`/api/auth/login?silent=0&next=${encodeURIComponent(longNext)}`, browser.header())));
    expect(browser.names().filter((n) => n.startsWith(`${names.flow}.`))).toHaveLength(MAX_LOGIN_FLOWS);
    expect(bytes(browser.header())).toBeLessThan(2048);
  });

  it('длинный next при этом сохраняется целиком во всех режимах', async () => {
    for (const mode of ['silent=0', 'silent=1', '']) {
      const h = createAuthHandlers({ env, fetch: service().fetch });
      const { callback } = await signIn(h, `${mode}&next=${encodeURIComponent(longNext)}`);
      expect(callback.headers.get('location')).toBe(APP + longNext);
    }
  });

  it('без cookie попытки обычный вход не притворяется тихой проверкой', async () => {
    const h = createAuthHandlers({ env, fetch: service().fetch });
    for (const mode of ['silent=0', '']) {
      const login = await h.GET(req(`/api/auth/login?${mode}&next=/x`));
      const state = new URL(login.headers.get('location')!).searchParams.get('state')!;
      const callback = await h.GET(req(`/api/auth/callback?error=login_required&state=${encodeURIComponent(state)}`));
      expect(callback.status).toBe(400);
    }
    const login = await h.GET(req('/api/auth/login?silent=1&next=/x'));
    const state = new URL(login.headers.get('location')!).searchParams.get('state')!;
    const callback = await h.GET(req(`/api/auth/callback?error=login_required&state=${encodeURIComponent(state)}`));
    expect(callback.headers.get('location')).toBe(`${APP}/x?${SILENT_CHECK_PARAM}=1`);
  });
});
