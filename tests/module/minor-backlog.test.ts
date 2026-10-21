import { describe, it, expect } from 'vitest';
import { createAuthHandlers } from '../../module/server/handlers.js';
import { createSessionGuard } from '../../module/server/session-guard.js';
import { seal } from '../../module/server/core/cookie-seal.js';
import { cookieNamesFor } from './helpers.js';

const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1';
const APP = 'https://app.test';
const env = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: APP, AUTH_COOKIE_SECRET: SECRET };
const { session: SESSION_COOKIE, flow: FLOW_COOKIE, logout: LOGOUT_COOKIE } = cookieNamesFor(env);

const noNetwork = (async () => new Response('')) as typeof fetch;
const authDown = (async () => Response.json({ error: 'server_error' }, { status: 503 })) as typeof fetch;

function fakeJwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(unescape(encodeURIComponent(JSON.stringify(o)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${b64({ alg: 'RS256' })}.${b64(payload)}.sig`;
}

async function expiredSession(): Promise<string> {
  const data = {
    user: { id: 'u1', roles: [] },
    accessToken: fakeJwt({ sub: 'u1' }),
    refreshToken: 'r1',
    accessTokenExpiresAt: Date.now() - 1000,
  };
  return `${SESSION_COOKIE}=${await seal(data, SECRET)}`;
}

describe('п.3/п.13: отказ на экране согласия возвращается в приложение', () => {
  async function startLogin() {
    const { GET } = createAuthHandlers({ env, fetch: noNetwork });
    const res = await GET(new Request(`${APP}/api/auth/login?next=/dashboard&silent=0`));
    const state = new URL(res.headers.get('location')!).searchParams.get('state')!;
    const flow = res.headers.getSetCookie().find((c) => c.startsWith(`${FLOW_COOKIE}.`))!;
    return { GET, state, cookie: flow.split(';')[0]! };
  }

  it('access_denied: понятный текст и стёртая cookie попытки', async () => {
    const { GET, state, cookie } = await startLogin();
    const res = await GET(new Request(`${APP}/api/auth/callback?error=access_denied&state=${encodeURIComponent(state)}`, {
      headers: { cookie },
    }));
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain('отказались');
    expect(html).toContain('Попробовать снова');
    expect(res.headers.getSetCookie().find((c) => c.startsWith(`${FLOW_COOKIE}.`))).toContain('Max-Age=0');
  });

  it('другая ошибка — прежний общий текст', async () => {
    const { GET, state, cookie } = await startLogin();
    const res = await GET(new Request(`${APP}/api/auth/callback?error=server_error&state=${encodeURIComponent(state)}`, {
      headers: { cookie },
    }));
    expect(await res.text()).not.toContain('отказались');
  });
});

describe('п.1: выход с устаревшей страницы подтверждения', () => {
  it('неверный csrf на своём origin — страница с пояснением и ссылкой на выход, без cookie', async () => {
    const handlers = createAuthHandlers({ env, fetch: noNetwork });
    const res = await handlers.POST(new Request(`${APP}/api/auth/logout`, {
      method: 'POST',
      headers: { origin: APP, cookie: `${LOGOUT_COOKIE}=stale` },
      body: new URLSearchParams({ csrf: 'stale' }),
    }));
    expect(res.status).toBe(403);
    expect(res.headers.get('content-type')).toContain('text/html');
    expect(res.headers.getSetCookie()).toEqual([]);
    const html = await res.text();
    expect(html).toContain('href="/api/auth/logout"');
    expect(html).toContain('href="/"');
    expect(html).not.toContain('Forbidden');
  });

  it('чужой origin — по-прежнему голый 403', async () => {
    const handlers = createAuthHandlers({ env, fetch: noNetwork });
    const res = await handlers.POST(new Request(`${APP}/api/auth/logout`, {
      method: 'POST', headers: { origin: 'https://evil.test' }, body: new URLSearchParams({ csrf: 'x' }),
    }));
    expect(res.status).toBe(403);
    expect(await res.text()).toBe('Forbidden');
  });
});

describe('п.21: сбой сервиса входа на защищённой странице', () => {
  const guard = () => createSessionGuard({ env, fetch: authDown, protect: ['/dashboard'] });

  it('переход по странице — HTML с повтором, а не сырой JSON', async () => {
    const decision = await guard()(new Request(`${APP}/dashboard`, {
      headers: { cookie: await expiredSession(), 'sec-fetch-mode': 'navigate', accept: 'text/html' },
    }));
    if (decision.kind !== 'deny') throw new Error('ожидали deny');
    const res = decision.response;
    expect(res.status).toBe(503);
    expect(res.headers.get('content-type')).toContain('text/html');
    expect(res.headers.get('retry-after')).toBe('5');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('vary')).toContain('Sec-Fetch-Mode');
    const html = await res.text();
    expect(html).toContain('Сервис входа временно недоступен');
    expect(html).toContain('http-equiv="refresh"');
    expect(html).not.toContain('temporarily_unavailable');
  });

  it('запрос данных (fetch) — JSON, как раньше', async () => {
    const decision = await guard()(new Request(`${APP}/dashboard/data`, {
      headers: { cookie: await expiredSession(), 'sec-fetch-mode': 'cors', accept: 'application/json' },
    }));
    if (decision.kind !== 'deny') throw new Error('ожидали deny');
    expect(decision.response.status).toBe(503);
    expect(decision.response.headers.get('content-type')).toContain('application/json');
    expect(await decision.response.json()).toEqual({ error: 'temporarily_unavailable' });
    expect(decision.response.headers.get('vary')).toContain('Sec-Fetch-Mode');
  });

  it('/api/auth/me при сбое остаётся JSON', async () => {
    const { GET } = createAuthHandlers({ env, fetch: authDown });
    const res = await GET(new Request(`${APP}/api/auth/me`, {
      headers: { cookie: await expiredSession(), 'sec-fetch-mode': 'navigate' },
    }));
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: 'temporarily_unavailable' });
  });
});
