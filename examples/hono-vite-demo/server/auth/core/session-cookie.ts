import { seal, unseal } from './cookie-seal.js';
import { decodeJwtClaims } from './claims.js';
import { isSessionData, type SessionData } from './session-data.js';
import { MAX_COOKIE_BYTES, SESSION_MAX_AGE, serializeCookie } from '../cookies.js';

// Cookie сессии. Роли отдельно не храним: они уже есть в access-токене и при
// чтении берутся оттуда. Так cookie растёт с числом ролей почти вдвое медленнее.

const byteLength = (s: string) => new TextEncoder().encode(s).length;

// Готовая строка Set-Cookie или null, если сессия не помещается в cookie:
// браузер молча выбросил бы её, и вход пошёл бы по кругу.
export async function sessionCookie(name: string, data: SessionData, secret: string, secure: boolean): Promise<string | null> {
  const { roles: _roles, ...user } = data.user;
  const sealed = await seal({ ...data, user }, secret, SESSION_MAX_AGE);
  if (byteLength(`${name}=${sealed}`) > MAX_COOKIE_BYTES) return null;
  return serializeCookie(name, sealed, { maxAgeSeconds: SESSION_MAX_AGE, secure });
}

// Сессия из cookie или null. Cookie прежних версий хранят роли сами.
export async function readSession(sealed: string | undefined, secret: string): Promise<SessionData | null> {
  if (!sealed) return null;
  const data = await unseal<{ user?: { roles?: unknown }; accessToken?: unknown }>(sealed, secret);
  if (data?.user && typeof data.user === 'object' && data.user.roles === undefined && typeof data.accessToken === 'string')
    data.user.roles = decodeJwtClaims(data.accessToken)?.roles ?? [];
  return isSessionData(data) ? data : null;
}
