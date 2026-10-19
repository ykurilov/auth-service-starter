import {
  MAX_BINDINGS_PER_CHAIN,
  type BrowserBinding,
  type SsoSession,
  type SsoSessionStore,
  type SsoStores,
} from '../../domain/sso/sso-session.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { SessionStore } from '../../domain/sessions/session.js';

// SsoStores без БД: один процесс. Отката нет — повторяемость выхода
// обеспечивает SsoSessionService. Блокировки цепочек, взятые внутри
// atomically, держатся до его конца, как advisory-блокировки до COMMIT.
export function inMemorySsoStores(sso: InMemorySsoSessionStore, sessions: SessionStore): SsoStores {
  return { sso, sessions, atomically: (fn) => sso.transaction(() => fn({ sso, sessions })) };
}

export class InMemorySsoSessionStore implements SsoSessionStore {
  private readonly sessions = new Map<string, SsoSession>();
  // Привязки браузеров по хешу секрета.
  private readonly bindings = new Map<string, BrowserBinding>();
  // Очередь блокировок цепочки: хвост — промис, который отпустит последний
  // вставший в очередь. Блокировки текущей транзакции — в heldChains.
  private readonly chainQueues = new Map<string, Promise<void>>();
  private readonly heldChains = new AsyncLocalStorage<Map<string, () => void>>();

  // Транзакция без БД: блокировки цепочек, взятые внутри fn, снимаются после
  // неё (и при сбое). Вложенный вызов — та же транзакция.
  async transaction<T>(fn: () => Promise<T>): Promise<T> {
    if (this.heldChains.getStore()) return fn();
    const held = new Map<string, () => void>();
    return this.heldChains.run(held, async () => {
      try {
        return await fn();
      } finally {
        for (const release of held.values()) release();
      }
    });
  }

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

  // Операции одной цепочки идут по очереди, как под pg_advisory_xact_lock.
  // Вне транзакции — дождаться держателя и сразу отпустить (как блокировка
  // в автокоммите Postgres).
  async lockChain(chainId: string): Promise<void> {
    const held = this.heldChains.getStore();
    if (held?.has(chainId)) return;
    let release!: () => void;
    const mine = new Promise<void>((resolve) => (release = resolve));
    const previous = this.chainQueues.get(chainId) ?? Promise.resolve();
    const tail = previous.then(() => mine);
    this.chainQueues.set(chainId, tail);
    const unlock = () => {
      release();
      // Очередь не копится в памяти: последний в ней убирает её за собой.
      if (this.chainQueues.get(chainId) === tail) this.chainQueues.delete(chainId);
    };
    await previous;
    if (held) held.set(chainId, unlock);
    else unlock();
  }

  async lockChains(chainIds: readonly string[]): Promise<void> {
    for (const chainId of [...new Set(chainIds)].sort()) await this.lockChain(chainId);
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

  async findBinding(tokenHash: string): Promise<BrowserBinding | null> {
    const b = this.bindings.get(tokenHash);
    return b ? { ...b } : null;
  }

  async addBinding(binding: BrowserBinding): Promise<void> {
    // Новая остаётся и при равных сроках, как в БД (token_hash <> новая).
    const others = [...this.bindings.values()]
      .filter((b) => b.chainId === binding.chainId)
      .sort((a, b) => b.expiresAt.getTime() - a.expiresAt.getTime());
    this.bindings.set(binding.tokenHash, { ...binding });
    for (const old of others.slice(MAX_BINDINGS_PER_CHAIN - 1)) this.bindings.delete(old.tokenHash);
  }

  async renewBinding(tokenHash: string, expiresAt: Date): Promise<boolean> {
    const b = this.bindings.get(tokenHash);
    if (!b) return false;
    b.expiresAt = expiresAt;
    return true;
  }

  async deleteBinding(tokenHash: string): Promise<void> {
    this.bindings.delete(tokenHash);
  }

  async deleteChainBindings(chainId: string): Promise<void> {
    for (const [hash, b] of this.bindings) if (b.chainId === chainId) this.bindings.delete(hash);
  }

  async browserDeadline(chainId: string): Promise<Date | null> {
    let deadline: number | null = null;
    for (const b of this.bindings.values()) {
      if (b.chainId === chainId && (deadline === null || b.expiresAt.getTime() > deadline)) deadline = b.expiresAt.getTime();
    }
    for (const s of this.sessions.values()) {
      if (s.chainId === chainId && (deadline === null || s.expiresAt.getTime() > deadline)) deadline = s.expiresAt.getTime();
    }
    return deadline === null ? null : new Date(deadline);
  }

  async deleteExpired(before: Date): Promise<number> {
    let deleted = 0;
    const cutoff = before.getTime();
    for (const [hash, b] of this.bindings) {
      if (b.expiresAt.getTime() < cutoff) {
        this.bindings.delete(hash);
        deleted++;
      }
    }
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
