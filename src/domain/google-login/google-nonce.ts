import { randomBytes } from 'node:crypto';
import type { Clock } from '../../ports/clock.js';
import { sha256Hex } from '../shared/hash.js';

// Одноразовый nonce для входа через Google. Выпускается сервером при показе
// кнопки, хранится на сервере (хешем) со сроком жизни и привязкой к браузеру
// (хеш csrf-cookie) и клиенту. Google возвращает его в claim nonce id_token;
// при входе он гасится атомарно — повторно предъявить тот же id_token нельзя
// ни из этого, ни из другого браузера, ни через другой экземпляр сервиса.
export interface GoogleNonceRecord {
  nonceHash: string;
  bindingHash: string;
  clientId: string;
  createdAt: Date;
  expiresAt: Date;
}

export interface GoogleNonceStore {
  save(record: GoogleNonceRecord): Promise<void>;
  // CAS: гасит nonce, только если он жив, не погашен и выпущен этому браузеру
  // для этого клиента. true — этот вызов погасил.
  consume(nonceHash: string, bindingHash: string, clientId: string, now: Date): Promise<boolean>;
  deleteExpired(before: Date): Promise<number>;
}

const DEFAULT_TTL_SECONDS = 600;

export class GoogleNonceService {
  constructor(
    private readonly store: GoogleNonceStore,
    private readonly clock: Clock,
    private readonly ttlSeconds = DEFAULT_TTL_SECONDS,
  ) {}

  async issue(binding: string, clientId: string): Promise<string> {
    const nonce = randomBytes(32).toString('base64url');
    const now = this.clock.now();
    await this.store.save({
      nonceHash: sha256Hex(`gnonce:${nonce}`),
      bindingHash: sha256Hex(`binding:${binding}`),
      clientId,
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.ttlSeconds * 1000),
    });
    return nonce;
  }

  async consume(nonce: string, binding: string, clientId: string): Promise<boolean> {
    if (!nonce || !binding) return false;
    return this.store.consume(
      sha256Hex(`gnonce:${nonce}`),
      sha256Hex(`binding:${binding}`),
      clientId,
      this.clock.now(),
    );
  }
}
