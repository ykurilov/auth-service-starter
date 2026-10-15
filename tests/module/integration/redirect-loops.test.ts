import { describe, it, expect } from 'vitest';
import { createAuthHandlers } from '../../../module/server/handlers.js';
import { createAuthMiddleware } from '../../../module/server/nextjs.js';
import { getUser, silentCheckDone } from '../../../module/server/server.js';
import { FLOW_COOKIE, SILENT_CHECK_COOKIE } from '../../../module/server/cookies.js';

// Модель браузера: ходит по редиректам между приложением (middleware → маршруты
// модуля или страница) и заглушкой сервиса авторизации, хранит cookie.
// Цель — убедиться, что любой сбой входа заканчивается страницей, а не кругом.

const APP = 'https://app.test';
const AUTH = 'https://auth.test';
const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1';
const env = { AUTH_URL: AUTH, AUTH_APP_URL: APP, AUTH_COOKIE_SECRET: SECRET };
const MAX_HOPS = 15;

function fakeJwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(unescape(encodeURIComponent(JSON.stringify(o))))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${b64({ alg: 'RS256' })}.${b64(payload)}.sig`;
}

type AuthorizeOutcome = 'login_required' | 'server_error' | 'access_denied' | 'code' | 'login_page';
type TokenOutcome = 'ok' | 'invalid_grant' | 'bad_tokens';

interface Scenario {
  protect: string[];
  // Что сервис отвечает на prompt=none и на обычный /authorize.
  silent: AuthorizeOutcome;
  interactive: AuthorizeOutcome;
  token?: TokenOutcome;
  cookiesEnabled?: boolean;
  // Перед callback «стираем» auth_flow и метку — как будто истекли.
  expireBeforeCallback?: boolean;
}

function tokenFetch(outcome: TokenOutcome): typeof fetch {
  return (async () => {
    if (outcome === 'invalid_grant') return Response.json({ error: 'invalid_grant' }, { status: 400 });
    // bad_tokens: у access-токена нет sub — buildSessionData вернёт null.
    const sub = outcome === 'ok' ? { sub: 'u1' } : {};
    return Response.json({
      access_token: fakeJwt({ ...sub, roles: [] }),
      id_token: fakeJwt({ ...sub }),
      refresh_token: 'r1',
      token_type: 'Bearer',
      expires_in: 900,
    });
  }) as typeof fetch;
}

// Публичная главная по примеру из README: тихо проверяем SSO один раз.
async function homePage(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const cookie = req.headers.get('cookie');
  const user = await getUser(cookie, { env });
  if (!user && !silentCheckDone(cookie, url.searchParams))
    return new Response(null, { status: 307, headers: { location: `${APP}/api/auth/login?silent=1&next=/` } });
  return new Response(user ? 'Привет' : 'Войти', { status: 200 });
}

async function browse(start: string, s: Scenario) {
  const handlers = createAuthHandlers({ env, fetch: tokenFetch(s.token ?? 'ok') });
  const mw = createAuthMiddleware({ env, fetch: tokenFetch('ok'), protect: s.protect });
  const jar = new Map<string, string>();
  const trail: string[] = [];

  const store = (res: Response) => {
    if (s.cookiesEnabled === false) return;
    for (const line of (res.headers as unknown as { getSetCookie(): string[] }).getSetCookie()) {
      const [pair] = line.split(';');
      const idx = pair!.indexOf('=');
      const name = pair!.slice(0, idx);
      if (/Max-Age=0/.test(line)) jar.delete(name);
      else jar.set(name, pair!.slice(idx + 1));
    }
  };
  const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');

  const app = async (url: URL): Promise<Response> => {
    const req = new Request(url, {
      headers: { cookie: cookieHeader(), 'sec-fetch-mode': 'navigate', accept: 'text/html' },
    });
    let passed = false;
    const res = await mw(req, () => {
      passed = true;
      return new Response(null, { status: 200 });
    });
    if (!passed) return res;
    store(res);
    if (url.pathname.startsWith('/api/auth/')) return handlers.GET(req);
    if (url.pathname === '/') return homePage(req);
    return new Response('страница', { status: 200 });
  };

  const authorize = (url: URL): Response => {
    const outcome = url.searchParams.get('prompt') === 'none' ? s.silent : s.interactive;
    if (outcome === 'login_page') return new Response('форма входа', { status: 200 });
    const cb = new URL(url.searchParams.get('redirect_uri')!);
    if (outcome === 'code') cb.searchParams.set('code', 'c1');
    else cb.searchParams.set('error', outcome);
    cb.searchParams.set('state', url.searchParams.get('state')!);
    if (s.expireBeforeCallback) {
      for (const key of jar.keys()) if (key.startsWith(`${FLOW_COOKIE}.`)) jar.delete(key);
      jar.delete(SILENT_CHECK_COOKIE);
    }
    return new Response(null, { status: 302, headers: { location: cb.toString() } });
  };

  let url = new URL(start);
  for (let hop = 0; hop < MAX_HOPS; hop++) {
    trail.push(url.toString());
    const res = url.origin === AUTH ? authorize(url) : await app(url);
    store(res);
    const location = res.headers.get('location');
    if (res.status < 300 || res.status >= 400 || !location) {
      return { res, url, trail, body: await res.text(), jar };
    }
    url = new URL(location, url);
  }
  throw new Error(`круг редиректов:\n${trail.join('\n')}`);
}

describe('публичная страница с тихой проверкой: сбои не зацикливаются', () => {
  const base = { protect: ['/dashboard'], interactive: 'login_page' as const };

  it('нет SSO-сессии -> главная с «Войти»', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'login_required' });
    expect(r.body).toBe('Войти');
  });

  it('SSO-сессия есть -> главная с пользователем', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'code' });
    expect(r.body).toBe('Привет');
    expect(r.jar.has(SILENT_CHECK_COOKIE)).toBe(false);
  });

  it('обмен кода стабильно падает -> главная', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'code', token: 'invalid_grant' });
    expect(r.body).toBe('Войти');
  });

  it('из токенов не собрать сессию -> главная', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'code', token: 'bad_tokens' });
    expect(r.body).toBe('Войти');
  });

  it('сервис ответил server_error -> главная', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'server_error' });
    expect(r.body).toBe('Войти');
  });

  it('auth_flow и метка истекли до callback -> главная', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'login_required', expireBeforeCallback: true });
    expect(r.body).toBe('Войти');
  });

  it('cookie отключены, SSO нет -> главная (стоп-кран в адресе)', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'login_required', cookiesEnabled: false });
    expect(r.body).toBe('Войти');
  });

  it('cookie отключены, SSO есть -> главная', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'code', cookiesEnabled: false });
    expect(r.body).toBe('Войти');
  });
});

describe('защищённый / : сбои ведут на страницу ошибки, а не на вход по кругу', () => {
  const base = { protect: ['/'] };

  it('SSO-сессия есть -> сразу в приложение', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'code', interactive: 'login_page' });
    expect(r.body).toBe('Привет');
  });

  it('нет SSO -> форма входа сервиса', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'login_required', interactive: 'login_page' });
    expect(r.url.origin).toBe(AUTH);
    expect(r.body).toBe('форма входа');
  });

  it('тихая проверка: server_error -> страница ошибки с «Попробовать снова»', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'server_error', interactive: 'login_page' });
    expect(r.url.pathname).toBe('/api/auth/callback');
    expect(r.res.status).toBe(400);
    expect(r.body).toContain('Попробовать снова');
  });

  it('обычный вход вернул ошибку -> страница ошибки', async () => {
    const r = await browse(`${APP}/`, { ...base, silent: 'login_required', interactive: 'access_denied' });
    expect(r.res.status).toBe(400);
    expect(r.body).toContain('Попробовать снова');
  });

  it('обмен кода падает -> страница ошибки', async () => {
    const r = await browse(`${APP}/`, {
      ...base,
      silent: 'code',
      interactive: 'login_page',
      token: 'invalid_grant',
    });
    expect(r.res.status).toBe(400);
  });

  it('cookie отключены -> страница ошибки', async () => {
    const r = await browse(`${APP}/`, {
      ...base,
      silent: 'login_required',
      interactive: 'login_page',
      cookiesEnabled: false,
    });
    expect(r.res.status).toBe(400);
    expect(r.body).toContain('cookie');
  });
});
