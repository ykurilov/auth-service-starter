import { loadModuleConfig, type LoadConfigOptions } from './core/config';
import { createSessionManager, type RetiredRefreshTokens } from './core/session-manager';
import { getUser } from './server';
import type { SessionUser } from './core/session-data';

// Защита запросов без привязки к фреймворку: по Web Request решает, пропустить
// запрос или отказать. Адаптеры (Next.js, Hono) лишь переводят решение на язык
// своего фреймворка.

export interface GuardOptions extends LoadConfigOptions {
  // Префиксы путей, требующих входа. Истёкший access при временном сбое
  // refresh даёт 503, окончательный отказ — 401/редирект; публичные пути анонимны.
  protect?: string[];
}

// pass — пропустить запрос: user — кто вошёл (null — аноним), setCookies —
// дописать к ответу приложения (обновлённая или стёртая сессия);
// unavailable — сессия есть, но обновить её сейчас не удалось (сбой сервиса).
// deny — вернуть response вместо ответа приложения (редирект на вход или 401).
export type GuardDecision =
  | { kind: 'pass'; user: SessionUser | null; setCookies: string[]; unavailable?: true }
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
function toLogin(appUrl: string, next: string, setCookies: string[]): Response {
  const url = new URL('/api/auth/login', appUrl);
  url.searchParams.set('next', next);
  const headers = new Headers({ location: url.toString(), vary: DENIED_VARY, 'cache-control': 'no-store' });
  for (const c of setCookies) headers.append('set-cookie', c);
  return new Response(null, { status: 302, headers });
}

// retired — реестр закрытых сессий; по умолчанию общий на процесс с
// обработчиками входа того же client_id.
export function createSessionGuard(options: GuardOptions = {}, retired?: RetiredRefreshTokens) {
  const config = loadModuleConfig(options);
  const resolve = createSessionManager(options, retired);
  const protect = options.protect ?? [];

  return async function check(request: Request): Promise<GuardDecision> {
    const url = new URL(request.url);
    // Ни guard, ни его ответ не должны восстанавливать cookie после logout.
    if (url.pathname.startsWith('/api/auth/')) return {
      kind: 'pass', user: await getUser(request.headers.get('cookie'), options), setCookies: [],
    };
    const result = await resolve(request.headers.get('cookie'));
    if (result.kind === 'active') return { kind: 'pass', user: result.data.user, setCookies: result.setCookies };
    if (!isProtected(url.pathname, protect)) return result.kind === 'unavailable'
      ? { kind: 'pass', user: null, setCookies: result.setCookies, unavailable: true }
      : { kind: 'pass', user: null, setCookies: result.setCookies };
    if (result.kind === 'unavailable') return { kind: 'deny', response: isPageNavigation(request)
      ? temporaryUnavailablePage() : temporaryUnavailable(DENIED_VARY) };
    // Стираем только то, что стёр resolve: закрытую выходом сессию не трогаем,
    // в браузере уже может быть cookie нового входа.
    return { kind: 'deny', response: isPageNavigation(request)
      ? toLogin(config.appUrl, url.pathname + url.search, result.setCookies) : unauthenticated(result.setCookies) };
  };
}

// vary — когда вид ответа зависит от заголовков запроса (см. защиту путей).
export function temporaryUnavailable(vary?: string): Response {
  return Response.json({ error: 'temporarily_unavailable' }, {
    status: 503, headers: { 'cache-control': 'no-store', 'retry-after': '5', ...(vary ? { vary } : {}) },
  });
}

// То же для перехода по странице: человеку нужен текст, а не сырой JSON.
// Страница сама повторяет запрос через 5 секунд (Retry-After — для клиентов,
// которые его понимают).
export function temporaryUnavailablePage(): Response {
  const html = '<!doctype html><html lang="ru"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta http-equiv="refresh" content="5">' +
    '<title>Сервис входа временно недоступен</title></head>' +
    '<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">' +
    '<h1>Сервис входа временно недоступен</h1>' +
    '<p>Страница сама обновится через несколько секунд. Если ошибка не проходит, зайдите позже.</p>' +
    '<p><a href="">Обновить сейчас</a> · <a href="/">На главную</a></p></body></html>';
  return new Response(html, {
    status: 503,
    headers: {
      'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'retry-after': '5', vary: DENIED_VARY,
    },
  });
}
