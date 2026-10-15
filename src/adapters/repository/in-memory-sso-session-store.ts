import type {
  SsoSession,
  SsoSessionStore,
} from '../../domain/sso/sso-session.js';

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
