import { loadModuleConfig, type LoadConfigOptions } from './core/config.js';
import { unseal } from './core/cookie-seal.js';
import { parseCookies, SESSION_COOKIE, SILENT_CHECK_COOKIE, SILENT_CHECK_PARAM, cookieName, isSecureAppUrl } from './cookies.js';
import { isSessionData, type SessionUser } from './core/session-data.js';

// Для серверных компонентов: только читаем cookie (middleware держит её свежей).
// Ставить cookie в серверных компонентах Next.js нельзя — поэтому здесь без refresh.
export async function getUser(
  cookieHeader: string | null,
  options: LoadConfigOptions = {},
): Promise<SessionUser | null> {
  const config = loadModuleConfig(options);
  const cookies = parseCookies(cookieHeader);
  const sealed = cookies[cookieName(SESSION_COOKIE, isSecureAppUrl(config.appUrl))];
  if (!sealed) return null;
  const data = await unseal(sealed, config.cookieSecret);
  return isSessionData(data) && data.accessTokenExpiresAt > Date.now() ? data.user : null;
}

// Для публичных страниц: тихая проверка SSO уже была и не нашла сессию.
// Если false и getUser вернул null — можно один раз отправить на
// /api/auth/login?silent=1&next=<эта страница>; если true — показать «Войти».
// searchParams страницы обязательны: при отключённых cookie метка приходит
// только в адресе возврата, и без неё страница уйдёт в круг редиректов.
export function silentCheckDone(
  cookieHeader: string | null,
  searchParams?: URLSearchParams | Record<string, string | string[] | undefined>,
  options: LoadConfigOptions = {},
): boolean {
  // Без конфигурации используем безопасное HTTPS-имя; localhost передаёт options.
  const appUrl = options.env?.AUTH_APP_URL ?? (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.AUTH_APP_URL;
  const name = cookieName(SILENT_CHECK_COOKIE, appUrl ? isSecureAppUrl(appUrl) : true);
  if (parseCookies(cookieHeader)[name] !== undefined) return true;
  if (!searchParams) return false;
  return searchParams instanceof URLSearchParams
    ? searchParams.has(SILENT_CHECK_PARAM)
    : searchParams[SILENT_CHECK_PARAM] !== undefined;
}
