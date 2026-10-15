import type {
  AuthorizationCodeRecord,
  AuthorizationCodeStore,
} from '../../domain/login/authorization-code.js';

export class InMemoryAuthorizationCodeStore implements AuthorizationCodeStore {
  private readonly records: AuthorizationCodeRecord[] = [];

  async save(record: AuthorizationCodeRecord): Promise<void> {
    this.records.push({ ...record, auth: { ...record.auth } });
  }

  async findActiveByHash(
    codeHash: string,
    now: Date,
  ): Promise<AuthorizationCodeRecord | null> {
    const found = this.records.find(
      (r) =>
        r.codeHash === codeHash &&
        r.consumedAt === null &&
        r.expiresAt.getTime() > now.getTime(),
    );
    return found ? { ...found, auth: { ...found.auth } } : null;
  }

  async consume(id: string, at: Date): Promise<boolean> {
    const record = this.records.find((r) => r.id === id);
    if (!record || record.consumedAt !== null) return false;
    record.consumedAt = at;
    return true;
  }

  // Гасит все непогашенные коды клиента (удаление или смена правил клиента).
  async invalidateForClient(clientId: string, at: Date): Promise<void> {
    for (const r of this.records) {
      if (r.clientId === clientId && r.consumedAt === null) r.consumedAt = at;
    }
  }

  async deleteExpired(before: Date): Promise<number> {
    const cutoff = before.getTime();
    const kept = this.records.filter((r) => r.expiresAt.getTime() >= cutoff);
    const deleted = this.records.length - kept.length;
    this.records.length = 0;
    this.records.push(...kept);
    return deleted;
  }
}
