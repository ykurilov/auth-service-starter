import { authCookieNames, parseCookies } from './cookies.js';
import { loadModuleConfig } from './core/config.js';
import { createSessionGuard, type GuardOptions } from './session-guard.js';

// Адаптер Next.js: middleware поверх общей защиты (session-guard.ts).

// Фабрика ответа «пропустить запрос дальше». В Next.js приложение передаёт
// (headers) => NextResponse.next({ request: { headers } }); сами мы такой ответ не соберём без импорта
// next/server — обычный Response 200 из middleware Next.js трактует как
// финальный ответ, а не как «продолжить».
export type NextHandler = (headers: Headers) => Response;

export type MiddlewareOptions = GuardOptions;

export function createAuthMiddleware(options: MiddlewareOptions = {}) {
  const check = createSessionGuard(options);
  const config = loadModuleConfig(options);
  const names = authCookieNames(config.clientId, config.appUrl);

  return async function middleware(request: Request, next: NextHandler): Promise<Response> {
    const decision = await check(request);
    if (decision.kind === 'deny') return decision.response;
    // Пропустить запрос дальше: берём ответ next() и дописываем к нему set-cookie.
    const headers = new Headers(request.headers);
    const cookies = parseCookies(headers.get('cookie'));
    for (const line of decision.setCookies) {
      const pair = line.split(';')[0]!;
      const idx = pair.indexOf('=');
      const name = pair.slice(0, idx);
      if (/Max-Age=0(?:;|$)/i.test(line)) delete cookies[name];
      else cookies[name] = pair.slice(idx + 1);
    }
    // Без пользователя SSR-запрос идёт анонимно. Временный сбой refresh на
    // публичной странице cookie не вырезает, а помечает запрос «тихая проверка
    // сделана»: страница по образцу из README покажет «Войти», а не уйдёт на
    // login?silent=1, который упрётся в тот же сбой. Браузер метку не получает.
    if (!decision.user && !new URL(request.url).pathname.startsWith('/api/auth/')) {
      if (decision.unavailable) cookies[names.silentCheck] = '1';
      else delete cookies[names.session];
    }
    headers.set('cookie', Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; '));
    const res = next(headers);
    // Совместимость с прежним () => NextResponse.next(): используем тот же
    // протокол request override, который генерирует NextResponse.next({request}).
    if (!res.headers.has('x-middleware-override-headers')) {
      const keys: string[] = [];
      headers.forEach((value, key) => { keys.push(key); res.headers.set(`x-middleware-request-${key}`, value); });
      res.headers.set('x-middleware-override-headers', keys.join(','));
    }
    const overrides = new Set((res.headers.get('x-middleware-override-headers') ?? '').split(',').map((k) => k.trim()).filter(Boolean));
    overrides.add('cookie');
    res.headers.set('x-middleware-override-headers', [...overrides].join(','));
    res.headers.set('x-middleware-request-cookie', headers.get('cookie') ?? '');
    for (const c of decision.setCookies) res.headers.append('set-cookie', c);
    return res;
  };
}
