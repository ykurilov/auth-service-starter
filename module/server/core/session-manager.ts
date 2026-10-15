import { loadModuleConfig, type LoadConfigOptions } from './config.js';
import { OidcClient, OidcError } from './oidc-client.js';
import { seal, unseal } from './cookie-seal.js';
import { buildSessionData, isSessionData, type SessionData } from './session-data.js';
import { SESSION_COOKIE, SESSION_MAX_AGE, cookieName, parseCookies, serializeCookie, clearCookie, isSecureAppUrl } from '../cookies.js';

export type SessionResult =
  | { kind: 'active'; data: SessionData; setCookies: string[] }
  | { kind: 'absent'; setCookies: string[] }
  | { kind: 'unavailable'; setCookies: string[] };

type RefreshResult = { kind: 'ok'; data: SessionData } | { kind: 'revoked' } | { kind: 'temporary' };

export function createSessionManager(options: LoadConfigOptions) {
  const config = loadModuleConfig(options);
  const secure = isSecureAppUrl(config.appUrl);
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
    const sealed = parseCookies(cookieHeader)[cookieName(SESSION_COOKIE, secure)];
    const data = sealed ? await unseal(sealed, config.cookieSecret) : null;
    const clear = () => [clearCookie(SESSION_COOKIE, secure)];
    if (!isSessionData(data)) return { kind: 'absent', setCookies: sealed ? clear() : [] };
    if (data.accessTokenExpiresAt - Date.now() > 120_000) return { kind: 'active', data, setCookies: [] };
    const result = await refresh(data);
    if (result.kind === 'revoked') return { kind: 'absent', setCookies: clear() };
    if (result.kind === 'temporary') return data.accessTokenExpiresAt > Date.now()
      ? { kind: 'active', data, setCookies: [] } : { kind: 'unavailable', setCookies: [] };
    return { kind: 'active', data: result.data, setCookies: [serializeCookie(SESSION_COOKIE,
      await seal(result.data, config.cookieSecret, SESSION_MAX_AGE), { maxAgeSeconds: SESSION_MAX_AGE, secure })] };
  };
}
