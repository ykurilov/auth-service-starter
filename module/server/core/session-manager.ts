import { loadModuleConfig, type LoadConfigOptions } from './config.js';
import { OidcClient, OidcError } from './oidc-client.js';
import { buildSessionData, type SessionData } from './session-data.js';
import { readSession, sessionCookie } from './session-cookie.js';
import { authCookieNames, parseCookies, clearCookie, isSecureAppUrl } from '../cookies.js';

export type SessionResult =
  | { kind: 'active'; data: SessionData; setCookies: string[] }
  | { kind: 'absent'; setCookies: string[] }
  | { kind: 'unavailable'; setCookies: string[] };

type RefreshResult = { kind: 'ok'; data: SessionData; cookie: string } | { kind: 'revoked' } | { kind: 'temporary' };

// Пауза после недоступности сервиса входа: пока он лежит, запросы не ждут его
// deadline по очереди, а сервис не получает шквал повторов.
export const REFRESH_RETRY_PAUSE_MS = 15_000;

// Сервис недоступен целиком: нет сети, истёк deadline или 5xx. Только тогда
// пауза касается всех сессий. 429, прочие 4xx и странный ответ — отказ одной
// сессии: сервис отвечает быстро, и чужим сессиям ждать незачем.
function serviceDown(err: unknown): boolean {
  return err instanceof OidcError &&
    (err.error === 'network_error' || err.error === 'timeout' || (err.status !== undefined && err.status >= 500));
}

// Refresh-токены сессий, закрытых выходом или новым входом в этом экземпляре
// приложения. Запоздавший ответ refresh такого токена не выдаёт
// Set-Cookie: иначе он вернул бы сессию после выхода или затёр бы сессию нового
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
  // Токены, от которых сервис отказался: повторно у него не спрашиваем.
  const rejected = createRetiredRefreshTokens();
  let pausedUntil = 0;
  async function refresh(data: SessionData): Promise<RefreshResult> {
    const existing = inflight.get(data.refreshToken);
    if (existing) return existing;
    const pending = (async (): Promise<RefreshResult> => {
      try {
        const tokens = await client.refreshTokens(data.refreshToken);
        const updated = buildSessionData({ ...tokens, now: new Date() });
        // Обновление не может сменить личность уже открытой сессии.
        if (!updated || updated.user.id !== data.user.id) return { kind: 'temporary' };
        const cookie = await sessionCookie(sessionName, updated, config.cookieSecret, secure);
        if (cookie) return { kind: 'ok', data: updated, cookie };
        // Новая сессия не помещается в cookie (выросло число ролей): хранить
        // её негде, а старый refresh-токен уже израсходован. Закрываем её.
        await client.revoke(updated.refreshToken);
        return { kind: 'revoked' };
      } catch (err) {
        if (serviceDown(err)) pausedUntil = Date.now() + REFRESH_RETRY_PAUSE_MS;
        return { kind: err instanceof OidcError && err.status === 400 && err.error === 'invalid_grant'
          ? 'revoked' : 'temporary' };
      }
    })().finally(() => inflight.delete(data.refreshToken));
    inflight.set(data.refreshToken, pending);
    return pending;
  }
  return async function resolve(cookieHeader: string | null): Promise<SessionResult> {
    const sealed = parseCookies(cookieHeader)[sessionName];
    const data = await readSession(sealed, config.cookieSecret);
    if (!data) return { kind: 'absent', setCookies: sealed ? [clearCookie(sessionName, secure)] : [] };
    if (data.accessTokenExpiresAt - Date.now() > 120_000) return { kind: 'active', data, setCookies: [] };
    // Сессия уже закрыта: ни обновлённой, ни стёртой cookie. Браузер к этому
    // моменту мог получить cookie нового входа, её трогать нельзя.
    if (retired.has(data.refreshToken) || rejected.has(data.refreshToken)) return { kind: 'absent', setCookies: [] };
    const result = Date.now() < pausedUntil ? { kind: 'temporary' as const } : await refresh(data);
    if (retired.has(data.refreshToken)) return { kind: 'absent', setCookies: [] };
    // Отказ сервиса cookie тоже не стирает: запрос мог уйти со старой cookie
    // до нового входа, и Max-Age=0 в его ответе стёр бы новую сессию. Мёртвую
    // cookie перезапишет следующий вход; до тех пор токен у сервиса повторно
    // не спрашивается.
    if (result.kind === 'revoked') {
      rejected.retire(data.refreshToken);
      return { kind: 'absent', setCookies: [] };
    }
    if (result.kind === 'temporary') return data.accessTokenExpiresAt > Date.now()
      ? { kind: 'active', data, setCookies: [] } : { kind: 'unavailable', setCookies: [] };
    return { kind: 'active', data: result.data, setCookies: [result.cookie] };
  };
}
