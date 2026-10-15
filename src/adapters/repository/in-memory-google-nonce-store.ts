import type { GoogleNonceRecord, GoogleNonceStore } from '../../domain/google-login/google-nonce.js';

interface Entry extends GoogleNonceRecord {
  consumedAt: Date | null;
}

export class InMemoryGoogleNonceStore implements GoogleNonceStore {
  private readonly entries = new Map<string, Entry>();

  async save(record: GoogleNonceRecord): Promise<void> {
    this.entries.set(record.nonceHash, { ...record, consumedAt: null });
  }

  async consume(nonceHash: string, bindingHash: string, clientId: string, now: Date): Promise<boolean> {
    const e = this.entries.get(nonceHash);
    if (
      !e ||
      e.consumedAt !== null ||
      e.bindingHash !== bindingHash ||
      e.clientId !== clientId ||
      e.expiresAt.getTime() <= now.getTime()
    ) {
      return false;
    }
    e.consumedAt = now;
    return true;
  }

  async deleteExpired(before: Date): Promise<number> {
    let removed = 0;
    for (const [k, e] of this.entries) {
      if (e.expiresAt.getTime() < before.getTime()) {
        this.entries.delete(k);
        removed++;
      }
    }
    return removed;
  }
}
