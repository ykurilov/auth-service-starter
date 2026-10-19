import { decodeJwtClaims } from './claims';
import type { TokenSet } from './oidc-client';

export interface SessionUser {
  id: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  roles: string[];
}

export interface SessionData {
  user: SessionUser;
  accessToken: string;
  refreshToken: string;
  // Абсолютный момент истечения access-токена (мс эпохи) — по нему middleware
  // решает, пора ли обновлять.
  accessTokenExpiresAt: number;
}

export interface BuildSessionInput extends TokenSet {
  now: Date;
}

// user собираем из claims: профиль (email/name/verified) — из id_token, роли —
// из access_token. Подпись не проверяем (см. claims.ts).
export function buildSessionData(input: BuildSessionInput): SessionData | null {
  const id = decodeJwtClaims(input.idToken);
  const access = decodeJwtClaims(input.accessToken);
  if (!id || typeof id.sub !== 'string' || !id.sub || !access || access.sub !== id.sub ||
      (access.roles !== undefined && (!Array.isArray(access.roles) || access.roles.some((r) => typeof r !== 'string'))) ||
      (id.email !== undefined && typeof id.email !== 'string') ||
      (id.name !== undefined && typeof id.name !== 'string') ||
      (id.email_verified !== undefined && typeof id.email_verified !== 'boolean') ||
      !Number.isSafeInteger(input.expiresIn) || input.expiresIn <= 0 || !input.refreshToken) return null;

  const now = input.now.getTime();
  if (!Number.isFinite(now)) return null;
  for (const claims of [id, access]) {
    if (claims.exp !== undefined && (!Number.isSafeInteger(claims.exp) || claims.exp * 1000 <= now)) return null;
  }
  const user: SessionUser = { id: id.sub, roles: access?.roles ?? [] };
  if (id.email !== undefined) user.email = id.email;
  if (id.email_verified !== undefined) user.emailVerified = id.email_verified;
  if (id.name !== undefined) user.name = id.name;

  return {
    user,
    accessToken: input.accessToken,
    refreshToken: input.refreshToken,
    accessTokenExpiresAt: Math.min(now + input.expiresIn * 1000, access.exp === undefined ? Infinity : access.exp * 1000),
  };
}

// Структура проверяется после расшифровки, а срок sealed-конверта — в unseal.
export function isSessionData(data: unknown): data is SessionData {
  const d = data as SessionData | null;
  return !!d && !!d.user && typeof d.user.id === 'string' && !!d.user.id &&
    Array.isArray(d.user.roles) && d.user.roles.every((r) => typeof r === 'string') &&
    typeof d.accessToken === 'string' && !!d.accessToken &&
    typeof d.refreshToken === 'string' && !!d.refreshToken && Number.isFinite(d.accessTokenExpiresAt);
}
