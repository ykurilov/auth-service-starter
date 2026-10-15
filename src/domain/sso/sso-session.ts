import { randomBytes } from 'node:crypto';
import type { AuthSnapshot } from '../login/authorization-code.js';

export interface SsoSession {
  id: string;
  userId: string;
  auth: AuthSnapshot;
  tokenHash: string;
  createdAt: Date;
  lastUsedAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface SsoSessionStore {
  save(session: SsoSession): Promise<void>;
  findByHash(tokenHash: string): Promise<SsoSession | null>;
  touch(id: string, lastUsedAt: Date, expiresAt: Date): Promise<void>;
  revoke(id: string, at: Date): Promise<void>;
  // Удаляет записи с expires_at < before ИЛИ (отозвана И revoked_at < before).
  // Возвращает число удалённых.
  deleteExpired(before: Date): Promise<number>;
}

export function generateSsoToken(): string {
  return randomBytes(32).toString('base64url');
}
