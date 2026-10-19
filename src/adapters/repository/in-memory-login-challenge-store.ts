import type {
  LoginChallengeRecord,
  LoginChallengeStore,
} from '../../domain/email-login/login-challenge.js';

// Эталон контракта LoginChallengeStore для dev и тестов (один процесс:
// операции синхронны внутри метода, поэтому атомарны как UPDATE в Postgres).
export class InMemoryLoginChallengeStore implements LoginChallengeStore {
  private readonly records: LoginChallengeRecord[] = [];

  private static copy(r: LoginChallengeRecord): LoginChallengeRecord {
    return { ...r, link: r.link ? { ...r.link } : null };
  }

  private alive(handleHash: string, bindingHash: string, now: Date): LoginChallengeRecord | undefined {
    return this.records.find(
      (r) =>
        r.handleHash === handleHash &&
        r.bindingHash === bindingHash &&
        r.consumedAt === null &&
        r.expiresAt.getTime() > now.getTime(),
    );
  }

  async create(record: LoginChallengeRecord): Promise<void> {
    if (this.records.some((r) => r.handleHash === record.handleHash)) {
      throw new Error('handle попытки уже существует');
    }
    this.records.push(InMemoryLoginChallengeStore.copy(record));
  }

  async find(handleHash: string, bindingHash: string, now: Date): Promise<LoginChallengeRecord | null> {
    const r = this.alive(handleHash, bindingHash, now);
    return r ? InMemoryLoginChallengeStore.copy(r) : null;
  }

  async claimAttempt(handleHash: string, bindingHash: string, now: Date): Promise<LoginChallengeRecord | null> {
    const r = this.alive(handleHash, bindingHash, now);
    if (!r || r.attempts >= r.maxAttempts) return null;
    r.attempts += 1;
    return InMemoryLoginChallengeStore.copy(r);
  }

  async reserveResend(handleHash: string, bindingHash: string, now: Date): Promise<LoginChallengeRecord | null> {
    const r = this.alive(handleHash, bindingHash, now);
    if (!r || r.resends >= r.maxResends || r.attempts >= r.maxAttempts) return null;
    r.resends += 1;
    return InMemoryLoginChallengeStore.copy(r);
  }

  async replaceCode(id: string, codeHash: string, expiresAt: Date, now: Date): Promise<boolean> {
    const r = this.records.find((x) => x.id === id);
    if (!r || r.consumedAt !== null || r.expiresAt.getTime() <= now.getTime()) return false;
    r.codeHash = codeHash;
    r.expiresAt = expiresAt;
    return true;
  }

  async releaseResend(id: string): Promise<void> {
    const r = this.records.find((x) => x.id === id);
    if (r && r.resends > 0) r.resends -= 1;
  }

  async consume(id: string, at: Date): Promise<boolean> {
    const r = this.records.find((x) => x.id === id);
    if (!r || r.consumedAt !== null) return false;
    r.consumedAt = at;
    return true;
  }

  async deleteExpired(before: Date): Promise<number> {
    let removed = 0;
    for (let i = this.records.length - 1; i >= 0; i--) {
      if (this.records[i]!.expiresAt.getTime() < before.getTime()) {
        this.records.splice(i, 1);
        removed++;
      }
    }
    return removed;
  }
}
