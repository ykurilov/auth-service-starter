// Имена и (де)сериализация cookie. Базовые имена ниже — без суффикса client_id;
// итоговые имена приложения даёт authCookieNames(). Атрибуты: HttpOnly, SameSite=Lax,
// Path=/. Secure добавляем всегда, кроме локальной http-разработки.
export const SESSION_COOKIE = '__Host-auth_session';
export const FLOW_COOKIE = '__Host-auth_flow';
// Метка «тихая проверка SSO уже сделана и ничего не дала». Пока она жива,
// вход не ходит на сервис с prompt=none повторно — так не бывает цикла
// тихих редиректов.
export const SILENT_CHECK_COOKIE = '__Host-auth_silent_checked';

export const SILENT_CHECK_PARAM = 'auth_silent_checked';
export const LOGOUT_COOKIE = '__Host-auth_logout';
// Незавершённых попыток входа в браузере не больше этого числа: новая
// вытесняет самую старую. Cookie попытки маленькая (next лежит в state), так
// что все вместе они занимают в заголовке Cookie около 1,6 КБ.
export const MAX_LOGIN_FLOWS = 4;
// Браузеры хранят cookie до 4096 байт на имя и значение; берём с запасом.
export const MAX_COOKIE_BYTES = 4000;

// HTTPS никогда не читает legacy-имена. HTTP localhost использует имена без префикса.
export function cookieName(name: string, secure: boolean): string {
  return secure ? name : name.replace(/^__Host-/, '');
}

export interface AuthCookieNames {
  session: string;
  // Префикс попыток входа: cookie попытки — `${flow}.<state>`.
  flow: string;
  silentCheck: string;
  logout: string;
}

// Браузер не разделяет cookie по портам: приложения на одном hostname видят
// cookie друг друга. Суффикс client_id разводит их имена, и модуль не читает и
// не стирает cookie соседа. Обычный client_id (hostname, slug) идёт как есть,
// остальные символы заменяются, а хеш сохраняет различие исходных id.
export function cookieSuffix(clientId: string): string {
  if (/^[A-Za-z0-9._-]{1,64}$/.test(clientId)) return clientId;
  let hash = 0x811c9dc5; // FNV-1a
  for (const byte of new TextEncoder().encode(clientId)) hash = Math.imul(hash ^ byte, 0x01000193) >>> 0;
  return `${clientId.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 48)}_${hash.toString(36)}`;
}

export function authCookieNames(clientId: string, appUrl: string): AuthCookieNames {
  const secure = isSecureAppUrl(appUrl);
  const suffix = cookieSuffix(clientId);
  const named = (base: string) => cookieName(`${base}.${suffix}`, secure);
  return { session: named(SESSION_COOKIE), flow: named(FLOW_COOKIE), silentCheck: named(SILENT_CHECK_COOKIE), logout: named(LOGOUT_COOKIE) };
}

export const SESSION_MAX_AGE = 30 * 24 * 3600; // 30 дней
// Попытка входа живёт час: код из письма действует 15 минут, и каждая из трёх
// переотправок продлевает его ещё на 15. Дольше не нужно и сервису.
export const FLOW_MAX_AGE = 60 * 60;
export const LOGOUT_MAX_AGE = 10 * 60; // 10 минут на подтверждение выхода
export const SILENT_CHECK_MAX_AGE = 5 * 60; // 5 минут

export interface CookieOptions {
  maxAgeSeconds: number;
  secure: boolean;
}

export function serializeCookie(name: string, value: string, opts: CookieOptions): string {
  const parts = [
    `${cookieName(name, opts.secure)}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${opts.maxAgeSeconds}`,
  ];
  if (opts.secure) parts.push('Secure');
  return parts.join('; ');
}

// Cookie для удаления: пустое значение + Max-Age=0.
export function clearCookie(name: string, secure: boolean): string {
  return serializeCookie(name, '', { maxAgeSeconds: 0, secure });
}

export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = Object.create(null);
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (name) out[name] = value;
  }
  return out;
}

// Secure решает адрес приложения, а не адрес запроса: за прокси сервер видит
// http://localhost, хотя браузер пришёл по https. Secure выключаем, только
// если само приложение живёт на http://localhost (иначе браузер не примет
// cookie на локалке). Всё остальное — Secure.
export function isSecureAppUrl(appUrl: string): boolean {
  const url = new URL(appUrl);
  return !(url.protocol === 'http:' && (['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)));
}
