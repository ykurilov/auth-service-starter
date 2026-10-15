import type { ClientType } from '../clients/client.js';

// Снимок аутентификации: провайдер + профиль на момент входа.
// Переносится через authorization code в grant, чтобы сессия/refresh
// перевыпускали id_token без повторного обращения к коду.
export interface AuthSnapshot {
  provider: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
}

// Результат успешного обмена кода: с чем идём выпускать токены (Фаза 3b).
export interface AuthorizationGrant {
  userId: string;
  clientId: string;
  // Тип клиента, по правилам которого вход решал, нужно ли согласие.
  clientType: ClientType;
  scope: string;
  nonce?: string;
  auth: AuthSnapshot;
}

// В хранилище — только SHA-256-хеш кода. Код привязан к клиенту, redirect_uri и PKCE-challenge.
export interface AuthorizationCodeRecord {
  id: string;
  codeHash: string;
  clientId: string;
  clientType: ClientType;
  userId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  nonce?: string;
  auth: AuthSnapshot;
  expiresAt: Date;
  consumedAt: Date | null;
}

export interface AuthorizationCodeStore {
  save(record: AuthorizationCodeRecord): Promise<void>;
  findActiveByHash(codeHash: string, now: Date): Promise<AuthorizationCodeRecord | null>;
  // Атомарно гасит код по id, только если ещё не погашен (CAS). true — этот вызов погасил.
  consume(id: string, at: Date): Promise<boolean>;
  // Удаляет записи с expires_at < before независимо от consumed (одноразовые
  // секреты после истечения бесполезны). Возвращает число удалённых.
  deleteExpired(before: Date): Promise<number>;
}
