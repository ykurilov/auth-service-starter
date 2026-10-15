import { createHash, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import type { Clock } from '../../ports/clock.js';
import { normalizeEmail } from '../identity/user.js';

// Одноразовый секрет, отправленный на почту (код или токен-ссылка).
// В хранилище — только SHA-256-хеш секрета, сам секрет живёт лишь в письме.
export interface EmailSecretRecord {
  id: string;
  purpose: string; // 'email-code-login' | 'email-verify' | ... — разделяет назначения
  email: string; // нормализованный
  secretHash: string; // sha256 hex
  expiresAt: Date;
  consumedAt: Date | null; // не null => уже погашен (одноразовость)
}

export interface EmailSecretStore {
  save(record: EmailSecretRecord): Promise<void>;
  // Самый свежий непогашенный и непросроченный секрет для пары (purpose, email).
  findActive(purpose: string, email: string, now: Date): Promise<EmailSecretRecord | null>;
  // Атомарно гасит секрет по id, ТОЛЬКО если он ещё не погашен.
  // true — этот вызов реально погасил (право использования за ним);
  // false — секрета нет или он уже погашен (проигрыш гонки/повтор). SQL: UPDATE ... WHERE consumed_at IS NULL.
  consume(id: string, at: Date): Promise<boolean>;
  // Гасит все активные секреты пары (purpose, email): новый запрос кода инвалидирует прежние.
  invalidateActive(purpose: string, email: string, at: Date): Promise<void>;
  // Удаляет записи с expires_at < before независимо от consumed. Возвращает число удалённых.
  deleteExpired(before: Date): Promise<number>;
}

export type SecretGenerator = () => string;

// 32 байта энтропии -> url-safe токен для ссылок подтверждения.
export const tokenGenerator: SecretGenerator = () => randomBytes(32).toString('base64url');

// Внимание: 6-значный код даёт всего ~1e6 вариантов — сама по себе одноразовость
// не спасает от перебора, верхний слой обязан ограничивать число попыток (rate-limit).
// Числовой код фиксированной длины для ввода руками (вход по коду).
export function numericCodeGenerator(digits = 6): SecretGenerator {
  const max = 10 ** digits;
  return () => randomInt(0, max).toString().padStart(digits, '0');
}

function hashSecret(secret: string): string {
  return createHash('sha256').update(secret).digest('hex');
}

function hashesEqual(storedHex: string, presented: string): boolean {
  const a = Buffer.from(storedHex, 'hex');
  const b = Buffer.from(hashSecret(presented), 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

export class EmailSecretService {
  constructor(
    private readonly store: EmailSecretStore,
    private readonly clock: Clock,
    private readonly generate: SecretGenerator = tokenGenerator,
    private readonly ttlSeconds = 15 * 60,
  ) {}

  // Генерирует секрет, сохраняет только его хеш со сроком жизни, возвращает сырой секрет для отправки на почту.
  async issue(purpose: string, rawEmail: string): Promise<string> {
    const email = normalizeEmail(rawEmail);
    const now = this.clock.now();
    // Новый секрет инвалидирует прежние активные для этой пары — валиден только последний код.
    await this.store.invalidateActive(purpose, email, now);
    const secret = this.generate();
    await this.store.save({
      id: randomUUID(),
      purpose,
      email,
      secretHash: hashSecret(secret),
      expiresAt: new Date(now.getTime() + this.ttlSeconds * 1000),
      consumedAt: null,
    });
    return secret;
  }

  // Проверяет предъявленный секрет и при успехе гасит его (одноразовость). Не бросает.
  async verify(purpose: string, rawEmail: string, presented: string): Promise<boolean> {
    const email = normalizeEmail(rawEmail);
    const now = this.clock.now();
    const record = await this.store.findActive(purpose, email, now);
    if (!record) return false;
    if (!hashesEqual(record.secretHash, presented)) return false;
    // Атомарное гашение: при гонке двух verify только один получит true.
    return this.store.consume(record.id, now);
  }
}
