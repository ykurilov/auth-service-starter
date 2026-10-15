import { loadModuleConfig, type LoadConfigOptions } from './config.js';
import { OidcClient, OidcError } from './oidc-client.js';
import { seal, unseal } from './cookie-seal.js';
import { buildSessionData, isSessionData, type SessionData } from './session-data.js';
import { SESSION_MAX_AGE, authCookieNames, parseCookies, serializeCookie, clearCookie, isSecureAppUrl } from '../cookies.js';

export type SessionResult =
  | { kind: 'active'; data: SessionData; setCookies: string[] }
  | { kind: 'absent'; setCookies: string[] }
  | { kind: 'unavailable'; setCookies: string[] };

type RefreshResult = { kind: 'ok'; data: SessionData } | { kind: 'revoked' } | { kind: 'temporary' };

// Refresh-токены сессий, закрытых выходом или новым входом в этом экземпляре
// приложения. Запоздавший ответ refresh такого токена не выдаёт Set-Cookie:
// иначе он вернул бы сессию после выхода или затёр бы сессию нового
// пользователя. Отметка живёт дольше любого refresh (deadline 10 секунд) и
// запроса, отправленного браузером до выхода.
export interface RetiredRefreshTokens {
  retire(refreshToken: string): void;
  has(refreshToken: string): boolean;
}

export function createRetiredRefreshTokens(ttlMs = 10 * 60_000, limit = 10_000): RetiredRefreshTokens {
  const expiresAt = new Map<string, number>(); // в порядке добавления
  function prune(now: number) {
    for (const [token, until] of expiresAt) {
      if (until > now && expiresAt.size <= limit) break;
      expiresAt.delete(token);
    }
  }
  return {
    retire(refreshToken) {
      const now = Date.now();
      expiresAt.delete(refreshToken);
      expiresAt.set(refreshToken, now + ttlMs);
      prune(now);
    },
    has(refreshToken) {
      const until = expiresAt.get(refreshToken);
      return until !== undefined && until > Date.now();
    },
  };
}

// Реестр по умолчанию — один на процесс для каждого client_id. Хранится в
// globalThis, а не в переменной модуля: Next.js собирает middleware и route
// handlers в разные бандлы, и у каждого была бы своя копия модуля. Edge
// runtime исполняет middleware в отдельной песочнице со своим globalThis —
// там реестр с Node-обработчиками не общий (см. README).
const SHARED_RETIRED = Symbol.for('auth-v3.module.retired-refresh-tokens');

export function sharedRetiredRefreshTokens(clientId: string): RetiredRefreshTokens {
  const global = globalThis as { [SHARED_RETIRED]?: Map<string, RetiredRefreshTokens> };
  const byClient = (global[SHARED_RETIRED] ??= new Map());
  let retired = byClient.get(clientId);
  if (!retired) byClient.set(clientId, (retired = createRetiredRefreshTokens()));
  return retired;
}

export function createSessionManager(options: LoadConfigOptions, retiredOverride?: RetiredRefreshTokens) {
  const config = loadModuleConfig(options);
  const retired = retiredOverride ?? sharedRetiredRefreshTokens(config.clientId);
  const secure = isSecureAppUrl(config.appUrl);
  const sessionName = authCookieNames(config.clientId, config.appUrl).session;
  const client = new OidcClient(config);
  const inflight = new Map<string, Promise<RefreshResult>>();
  async function refresh(data: SessionData): Promise<RefreshResult> {
    const existing = inflight.get(data.refreshToken);
    if (existing) return existing;
    const pending = (async (): Promise<RefreshResult> => {
      try {
        const tokens = await client.refreshTokens(data.refreshToken);
        const updated = buildSessionData({ ...tokens, now: new Date() });
        // Обновление не может сменить личность уже открытой сессии.
        return updated && updated.user.id === data.user.id ? { kind: 'ok', data: updated } : { kind: 'temporary' };
      } catch (err) {
        return { kind: err instanceof OidcError && err.status === 400 && err.error === 'invalid_grant'
          ? 'revoked' : 'temporary' };
      }
    })().finally(() => inflight.delete(data.refreshToken));
    inflight.set(data.refreshToken, pending);
    return pending;
  }
  return async function resolve(cookieHeader: string | null): Promise<SessionResult> {
    const sealed = parseCookies(cookieHeader)[sessionName];
    const data = sealed ? await unseal(sealed, config.cookieSecret) : null;
    const clear = () => [clearCookie(sessionName, secure)];
    if (!isSessionData(data)) return { kind: 'absent', setCookies: sealed ? clear() : [] };
    if (data.accessTokenExpiresAt - Date.now() > 120_000) return { kind: 'active', data, setCookies: [] };
    // Сессия уже закрыта: ни обновлённой, ни стёртой cookie. Браузер к этому
    // моменту мог получить cookie нового входа, её трогать нельзя.
    if (retired.has(data.refreshToken)) return { kind: 'absent', setCookies: [] };
    const result = await refresh(data);
    if (retired.has(data.refreshToken)) return { kind: 'absent', setCookies: [] };
    if (result.kind === 'revoked') return { kind: 'absent', setCookies: clear() };
    if (result.kind === 'temporary') return data.accessTokenExpiresAt > Date.now()
      ? { kind: 'active', data, setCookies: [] } : { kind: 'unavailable', setCookies: [] };
    return { kind: 'active', data: result.data, setCookies: [serializeCookie(sessionName,
      await seal(result.data, config.cookieSecret, SESSION_MAX_AGE), { maxAgeSeconds: SESSION_MAX_AGE, secure })] };
  };
}
