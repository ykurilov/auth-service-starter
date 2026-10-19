import type {
  SsoSession,
  SsoSessionStore,
  SsoStores,
} from '../../domain/sso/sso-session.js';
import type { SessionStore } from '../../domain/sessions/session.js';

// SsoStores без БД: один процесс, изменения не прерываются вводом-выводом.
// Транзакции нет — повторяемость выхода обеспечивает SsoSessionService.
export function inMemorySsoStores(sso: SsoSessionStore, sessions: SessionStore): SsoStores {
  return { sso, sessions, atomically: (fn) => fn({ sso, sessions }) };
}

export class InMemorySsoSessionStore implements SsoSessionStore {
  private readonly sessions = new Map<string, SsoSession>();

  private static copy(s: SsoSession): SsoSession {
    return { ...s, auth: { ...s.auth } };
  }

  async save(session: SsoSession): Promise<void> {
    this.sessions.set(session.id, InMemorySsoSessionStore.copy(session));
  }

  async findByHash(tokenHash: string): Promise<SsoSession | null> {
    for (const s of this.sessions.values()) {
      if (s.tokenHash === tokenHash) return InMemorySsoSessionStore.copy(s);
    }
    return null;
  }

  async findByLogin(loginId: string): Promise<SsoSession | null> {
    for (const s of this.sessions.values()) {
      if (s.auth.loginId === loginId) return InMemorySsoSessionStore.copy(s);
    }
    return null;
  }

  async findLatestInChain(chainId: string): Promise<SsoSession | null> {
    let latest: SsoSession | null = null;
    // При равном времени — записанная позже.
    for (const s of this.sessions.values()) {
      if (s.chainId === chainId && (!latest || s.createdAt.getTime() >= latest.createdAt.getTime())) latest = s;
    }
    return latest ? InMemorySsoSessionStore.copy(latest) : null;
  }

  async holdSignedIn(chainId: string, userId: string): Promise<boolean> {
    for (const s of this.sessions.values()) {
      if (s.chainId === chainId && s.userId === userId && s.revokedAt === null) return true;
    }
    return false;
  }

  async touch(id: string, lastUsedAt: Date, expiresAt: Date): Promise<void> {
    const s = this.sessions.get(id);
    if (!s) return;
    s.lastUsedAt = lastUsedAt;
    s.expiresAt = expiresAt;
  }

  async revoke(id: string, at: Date): Promise<void> {
    const s = this.sessions.get(id);
    if (!s) return;
    s.revokedAt = at;
  }

  async revokeChain(chainId: string, at: Date): Promise<void> {
    for (const s of this.sessions.values()) {
      if (s.chainId === chainId && s.revokedAt === null) s.revokedAt = at;
    }
  }

  async deleteExpired(before: Date): Promise<number> {
    let deleted = 0;
    const cutoff = before.getTime();
    for (const [id, s] of this.sessions) {
      const expired = s.expiresAt.getTime() < cutoff;
      const revokedLongAgo = s.revokedAt !== null && s.revokedAt.getTime() < cutoff;
      if (expired || revokedLongAgo) {
        this.sessions.delete(id);
        deleted++;
      }
    }
    return deleted;
  }
}
