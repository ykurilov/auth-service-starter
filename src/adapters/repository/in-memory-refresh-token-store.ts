import type {
  RefreshTokenRecord,
  RefreshTokenStore,
} from '../../domain/sessions/refresh-token.js';

export class InMemoryRefreshTokenStore implements RefreshTokenStore {
  private readonly records: RefreshTokenRecord[] = [];

  private static copy(r: RefreshTokenRecord): RefreshTokenRecord {
    return { ...r };
  }

  async save(record: RefreshTokenRecord): Promise<void> {
    this.records.push(InMemoryRefreshTokenStore.copy(record));
  }

  async findByHash(tokenHash: string): Promise<RefreshTokenRecord | null> {
    const r = this.records.find((x) => x.tokenHash === tokenHash);
    return r ? InMemoryRefreshTokenStore.copy(r) : null;
  }

  async findById(id: string): Promise<RefreshTokenRecord | null> {
    const r = this.records.find((x) => x.id === id);
    return r ? InMemoryRefreshTokenStore.copy(r) : null;
  }

  async rotate(headId: string, successor: RefreshTokenRecord, at: Date): Promise<boolean> {
    const head = this.records.find((r) => r.id === headId);
    if (!head || head.consumedAt !== null) return false;
    if (successor.sessionId !== head.sessionId || successor.previousTokenId !== headId ||
        this.records.some((r) => r.id === successor.id || r.tokenHash === successor.tokenHash)) {
      throw new Error('invalid refresh successor');
    }
    // No await between validation and publication.
    this.records.push(InMemoryRefreshTokenStore.copy(successor));
    head.consumedAt = at;
    head.replacedById = successor.id;
    return true;
  }

  async consume(id: string, replacedById: string, at: Date): Promise<boolean> {
    const r = this.records.find((x) => x.id === id);
    if (!r || r.consumedAt !== null) return false;
    r.consumedAt = at;
    r.replacedById = replacedById;
    return true;
  }

  // Не часть RefreshTokenStore: внутренний хук для каскадного удаления при
  // чистке сессий (InMemorySessionStore.deleteExpired), как в pg — удаление
  // refresh_tokens по session_id перед удалением самих сессий.
  deleteBySessionIds(sessionIds: ReadonlySet<string>): void {
    const kept = this.records.filter((r) => !sessionIds.has(r.sessionId));
    this.records.length = 0;
    this.records.push(...kept);
  }
}
