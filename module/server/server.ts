import { loadAppIdentity, loadModuleConfig, type LoadConfigOptions } from './core/config.js';
import { unseal } from './core/cookie-seal.js';
import { parseCookies, SILENT_CHECK_PARAM, authCookieNames } from './cookies.js';
import { isSessionData, type SessionUser } from './core/session-data.js';

// Для серверных компонентов: только читаем cookie (middleware держит её свежей).
// Ставить cookie в серверных компонентах Next.js нельзя — поэтому здесь без refresh.
export async function getUser(
  cookieHeader: string | null,
  options: LoadConfigOptions = {},
): Promise<SessionUser | null> {
  const config = loadModuleConfig(options);
  const cookies = parseCookies(cookieHeader);
  const sealed = cookies[authCookieNames(config.clientId, config.appUrl).session];
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
  // Имя метки зависит от адреса приложения и client_id; секрет не нужен.
  // Без AUTH_APP_URL страница не падает: признаём метку с любым client id.
  // Ошибиться так можно только в сторону «проверка была» — пропустить один
  // тихий вход, но не уйти в круг редиректов. Сами обработчики входа без
  // AUTH_APP_URL не создаются, так что ошибка конфигурации видна сразу.
  let identity: { appUrl: string; clientId: string } | null = null;
  try { identity = loadAppIdentity(options); } catch { /* см. выше */ }
  const cookies = parseCookies(cookieHeader);
  if (identity ? cookies[authCookieNames(identity.clientId, identity.appUrl).silentCheck] !== undefined
    : Object.keys(cookies).some((name) => /^(?:__Host-)?auth_silent_checked\./.test(name))) return true;
  if (!searchParams) return false;
  return searchParams instanceof URLSearchParams
    ? searchParams.has(SILENT_CHECK_PARAM)
    : searchParams[SILENT_CHECK_PARAM] !== undefined;
}
