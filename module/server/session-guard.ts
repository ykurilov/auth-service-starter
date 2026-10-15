import { loadModuleConfig, type LoadConfigOptions } from './core/config.js';
import { createSessionManager } from './core/session-manager.js';
import { getUser } from './server.js';
import type { SessionUser } from './core/session-data.js';
import { SESSION_COOKIE, clearCookie, isSecureAppUrl } from './cookies.js';

// Защита запросов без привязки к фреймворку: по Web Request решает, пропустить
// запрос или отказать. Адаптеры (Next.js, Hono) лишь переводят решение на язык
// своего фреймворка.

export interface GuardOptions extends LoadConfigOptions {
  // Префиксы путей, требующих входа. Истёкший access при временном сбое
  // refresh даёт 503, окончательный отказ — 401/редирект; публичные пути анонимны.
  protect?: string[];
}

// pass — пропустить запрос: user — кто вошёл (null — аноним), setCookies —
// дописать к ответу приложения (обновлённая или стёртая сессия).
// deny — вернуть response вместо ответа приложения (редирект на вход или 401).
export type GuardDecision =
  | { kind: 'pass'; user: SessionUser | null; setCookies: string[] }
  | { kind: 'deny'; response: Response };

function isProtected(pathname: string, protect: string[]): boolean {
  return protect.some((p) => pathname === p || pathname.startsWith(p.endsWith('/') ? p : p + '/'));
}

// Переход по странице (адресная строка, ссылка) или запрос данных (fetch,
// RSC-запрос Next.js)? Браузеры шлют Sec-Fetch-Mode; у старых смотрим Accept.
// Без Sec-Fetch-Mode запросом данных считаем только явный Accept без html и
// без */*; curl и старые клиенты получают редирект, как раньше.
function isPageNavigation(request: Request): boolean {
  const mode = request.headers.get('sec-fetch-mode');
  if (mode) return mode === 'navigate';
  const accept = request.headers.get('accept');
  return !accept || accept.includes('text/html') || accept.includes('*/*');
}

// Ответ отказа зависит от этих заголовков — кэши не должны его смешивать.
const DENIED_VARY = 'Sec-Fetch-Mode, Accept';

// Запросу данных редирект на вход бесполезен: fetch не пройдёт вход на чужом
// домене. Отвечаем 401, как /api/auth/me; клиент обрабатывает его и при
// необходимости начинает вход через навигацию страницы.
function unauthenticated(setCookies: string[]): Response {
  const headers = new Headers({ 'content-type': 'application/json', vary: DENIED_VARY, 'cache-control': 'no-store' });
  for (const c of setCookies) headers.append('set-cookie', c);
  return new Response(JSON.stringify({ error: 'unauthenticated' }), { status: 401, headers });
}

// Вход сам начнёт с тихой проверки SSO (prompt=none) — см. handlers.ts.
function toLogin(appUrl: string, next: string, clearCookieStr: string): Response {
  const url = new URL('/api/auth/login', appUrl);
  url.searchParams.set('next', next);
  const headers = new Headers({ location: url.toString(), vary: DENIED_VARY, 'cache-control': 'no-store' });
  headers.append('set-cookie', clearCookieStr);
  return new Response(null, { status: 302, headers });
}

export function createSessionGuard(options: GuardOptions = {}) {
  const config = loadModuleConfig(options);
  const resolve = createSessionManager(options);
  const protect = options.protect ?? [];

  return async function check(request: Request): Promise<GuardDecision> {
    const url = new URL(request.url);
    // Ни guard, ни его ответ не должны восстанавливать cookie после logout.
    if (url.pathname.startsWith('/api/auth/')) return {
      kind: 'pass', user: await getUser(request.headers.get('cookie'), options), setCookies: [],
    };
    const result = await resolve(request.headers.get('cookie'));
    if (result.kind === 'active') return { kind: 'pass', user: result.data.user, setCookies: result.setCookies };
    if (!isProtected(url.pathname, protect)) return { kind: 'pass', user: null, setCookies: result.setCookies };
    if (result.kind === 'unavailable') return { kind: 'deny', response: temporaryUnavailable() };
    const clear = clearCookie(SESSION_COOKIE, isSecureAppUrl(config.appUrl));
    return { kind: 'deny', response: isPageNavigation(request)
      ? toLogin(config.appUrl, url.pathname + url.search, clear) : unauthenticated([clear]) };
  };
}

export function temporaryUnavailable(): Response {
  return Response.json({ error: 'temporarily_unavailable' }, {
    status: 503, headers: { 'cache-control': 'no-store', 'retry-after': '5' },
  });
}
