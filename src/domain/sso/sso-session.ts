import { randomBytes } from 'node:crypto';
import type { AuthSnapshot } from '../login/authorization-code.js';
import type { SessionStore } from '../sessions/session.js';

export interface SsoSession {
  id: string;
  userId: string;
  // auth.loginId — вход, которым начата сессия: коды, выданные этим входом
  // и тихими входами через эту SSO-сессию, несут тот же loginId.
  auth: AuthSnapshot;
  tokenHash: string;
  // Цепочка SSO-сессий одного браузера: новая сессия, сменившая прежнюю
  // sso-cookie, наследует её цепочку. Сессии приложений, выданные через
  // цепочку, помнят её (Session.ssoChainId) и гаснут при смене аккаунта
  // в браузере и при выходе.
  chainId: string;
  createdAt: Date;
  lastUsedAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface SsoSessionStore {
  save(session: SsoSession): Promise<void>;
  // Находит сессию и после отзыва или истечения: выход повторяем по старой cookie.
  findByHash(tokenHash: string): Promise<SsoSession | null>;
  // Сессия, начатая входом loginId (auth.loginId), в любом состоянии. У
  // каждого входа своя SSO-сессия.
  findByLogin(loginId: string): Promise<SsoSession | null>;
  // Последняя по времени создания сессия цепочки (её cookie сейчас у браузера).
  findLatestInChain(chainId: string): Promise<SsoSession | null>;
  // Есть ли в цепочке неотозванная сессия этого пользователя. В БД найденные
  // строки удерживаются (FOR SHARE) до конца транзакции: выход и смена
  // аккаунта, которые их отзывают, ждут её фиксации.
  holdSignedIn(chainId: string, userId: string): Promise<boolean>;
  touch(id: string, lastUsedAt: Date, expiresAt: Date): Promise<void>;
  revoke(id: string, at: Date): Promise<void>;
  // Отзывает все ещё живые сессии цепочки.
  revokeChain(chainId: string, at: Date): Promise<void>;
  // Удаляет записи с expires_at < before ИЛИ (отозвана И revoked_at < before).
  // Возвращает число удалённых.
  deleteExpired(before: Date): Promise<number>;
}

export interface SsoStoreSet {
  sso: SsoSessionStore;
  sessions: SessionStore;
}

// Хранилища SSO-сессий и сессий приложений. atomically — изменения обоих одной
// транзакцией (в памяти — просто вызов): смена аккаунта и выход не оставляют
// SSO-сессию отозванной, а сессии приложений живыми.
export interface SsoStores extends SsoStoreSet {
  atomically<T>(fn: (stores: SsoStoreSet) => Promise<T>): Promise<T>;
}

export function generateSsoToken(): string {
  return randomBytes(32).toString('base64url');
}
