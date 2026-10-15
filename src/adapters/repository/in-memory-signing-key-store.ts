import type {
  SigningKeyStore,
  StoredSigningKey,
} from '../../domain/tokens/signing-key-store.js';

// In-memory эталон SigningKeyStore. Copy-on-read: наружу отдаются копии, чтобы
// вызывающий не мутировал внутреннее состояние.
export class InMemorySigningKeyStore implements SigningKeyStore {
  private readonly records: StoredSigningKey[] = [];

  private static copy(r: StoredSigningKey): StoredSigningKey {
    return { ...r };
  }

  async listAll(): Promise<StoredSigningKey[]> {
    return this.records.map(InMemorySigningKeyStore.copy);
  }

  async getActive(): Promise<StoredSigningKey | null> {
    const r = this.records.find((x) => x.status === 'active');
    return r ? InMemorySigningKeyStore.copy(r) : null;
  }

  async insertActive(key: StoredSigningKey): Promise<void> {
    this.records.push(InMemorySigningKeyStore.copy(key));
  }

  async ensureActive(key: StoredSigningKey): Promise<StoredSigningKey> {
    const existing = this.records.find((x) => x.status === 'active');
    if (existing) return InMemorySigningKeyStore.copy(existing);
    this.records.push(InMemorySigningKeyStore.copy(key));
    return InMemorySigningKeyStore.copy(key);
  }

  async rotate(newActive: StoredSigningKey, at: Date): Promise<string[]> {
    const retired: string[] = [];
    for (const r of this.records) {
      if (r.status === 'active') {
        r.status = 'retired';
        r.retiredAt = at;
        retired.push(r.kid);
      }
    }
    this.records.push(InMemorySigningKeyStore.copy(newActive));
    return retired;
  }

  async revoke(kid: string, at: Date): Promise<void> {
    const r = this.records.find((x) => x.kid === kid);
    if (r) r.revokedAt = at;
  }
}
