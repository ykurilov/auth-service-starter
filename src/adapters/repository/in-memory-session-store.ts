import type {
  Session,
  SessionStore,
  DeviceAudit,
} from '../../domain/sessions/session.js';
import { InMemoryRefreshTokenStore } from './in-memory-refresh-token-store.js';

export class InMemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, Session>();

  // Refresh-токены живут в отдельном сторе (своя таблица в pg), но контракт
  // deleteExpired обязан гасить их вместе с сессией — как и pg-адаптер в
  // одной транзакции. Стор внедряется, чтобы удалять именно те токены,
  // которыми пользуется остальной домен (SessionService), а не отдельную копию.
  constructor(private readonly refreshTokens: InMemoryRefreshTokenStore) {}

  private static copy(s: Session): Session {
    return { ...s, profile: { ...s.profile } };
  }

  async save(session: Session): Promise<void> {
    this.sessions.set(session.id, InMemorySessionStore.copy(session));
  }

  async findById(id: string): Promise<Session | null> {
    const s = this.sessions.get(id);
    return s ? InMemorySessionStore.copy(s) : null;
  }

  async touch(id: string, at: Date, expiresAt: Date, device: DeviceAudit): Promise<void> {
    const s = this.sessions.get(id);
    if (!s) return;
    s.lastUsedAt = at;
    s.expiresAt = expiresAt;
    s.deviceFingerprint = device.fingerprint;
    s.ipHash = device.ipHash;
  }

  async revoke(id: string, at: Date): Promise<void> {
    const s = this.sessions.get(id);
    if (s) s.revokedAt = at;
  }

  async revokeForClient(clientId: string, at: Date, allowedProviders: string[] = []): Promise<void> {
    for (const s of this.sessions.values()) {
      if (s.clientId === clientId && s.revokedAt === null && !allowedProviders.includes(s.provider)) {
        s.revokedAt = at;
      }
    }
  }

  async revokeForUser(userId: string, at: Date): Promise<void> {
    for (const s of this.sessions.values()) {
      if (s.userId === userId && s.revokedAt === null) s.revokedAt = at;
    }
  }

  async revokeForSsoChain(chainId: string, at: Date, userId?: string): Promise<void> {
    for (const s of this.sessions.values()) {
      if (s.revokedAt === null && (s.ssoChainId === chainId || (userId !== undefined && s.userId === userId))) {
        s.revokedAt = at;
      }
    }
  }

  async findActiveByUser(userId: string, now: Date): Promise<Session[]> {
    return [...this.sessions.values()]
      .filter(
        (s) =>
          s.userId === userId &&
          s.revokedAt === null &&
          s.expiresAt.getTime() > now.getTime(),
      )
      .map(InMemorySessionStore.copy);
  }

  async deleteExpired(before: Date): Promise<number> {
    const cutoff = before.getTime();
    const toDelete = new Set<string>();
    for (const [id, s] of this.sessions) {
      const expired = s.expiresAt.getTime() < cutoff;
      const revokedLongAgo = s.revokedAt !== null && s.revokedAt.getTime() < cutoff;
      if (expired || revokedLongAgo) toDelete.add(id);
    }
    // Сначала гасим refresh-токены удаляемых сессий (как pg — в одной
    // транзакции), затем сами сессии.
    this.refreshTokens.deleteBySessionIds(toDelete);
    for (const id of toDelete) this.sessions.delete(id);
    return toDelete.size;
  }
}
