import type {
  EmailSecretRecord,
  EmailSecretStore,
} from '../../domain/email-secret/email-secret.js';

export class InMemoryEmailSecretStore implements EmailSecretStore {
  private readonly records: EmailSecretRecord[] = [];

  async save(record: EmailSecretRecord): Promise<void> {
    this.records.push({ ...record });
  }

  async findActive(
    purpose: string,
    email: string,
    now: Date,
  ): Promise<EmailSecretRecord | null> {
    const active = this.records.filter(
      (r) =>
        r.purpose === purpose &&
        r.email === email &&
        r.consumedAt === null &&
        r.expiresAt.getTime() > now.getTime(),
    );
    if (active.length === 0) return null;
    // Самый свежий по сроку истечения (выдан позже -> истекает позже).
    const latest = active.reduce((a, b) =>
      b.expiresAt.getTime() > a.expiresAt.getTime() ? b : a,
    );
    return { ...latest };
  }

  async consume(id: string, at: Date): Promise<boolean> {
    const record = this.records.find((r) => r.id === id);
    if (!record || record.consumedAt !== null) return false;
    record.consumedAt = at;
    return true;
  }

  async invalidateActive(purpose: string, email: string, at: Date): Promise<void> {
    for (const r of this.records) {
      if (r.purpose === purpose && r.email === email && r.consumedAt === null) {
        r.consumedAt = at;
      }
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
