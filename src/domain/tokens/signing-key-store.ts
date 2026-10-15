// Порт хранилища ключей подписи. Домен зависит только от этого интерфейса,
// а не от конкретного адаптера (pg / in-memory). Ключи хранятся в PEM, чтобы
// не тащить в стор непереносимые KeyLike-объекты драйвера jose.
export type SigningKeyStatus = 'active' | 'retired';

export interface StoredSigningKey {
  kid: string;
  privatePem: string;
  publicPem: string;
  alg: string;
  status: SigningKeyStatus;
  createdAt: Date;
  retiredAt: Date | null;
  // Аварийный отзыв: не null → ключ скомпрометирован и исключён из набора
  // верификации (в отличие от retired, который ещё проверяет свои токены).
  revokedAt: Date | null;
}

export interface SigningKeyStore {
  listAll(): Promise<StoredSigningKey[]>;
  getActive(): Promise<StoredSigningKey | null>;
  insertActive(key: StoredSigningKey): Promise<void>;
  // Идемпотентный сид: гарантирует наличие active-ключа. Пытается вставить key;
  // при гонке (другой инстанс уже создал active) уступает без ошибки и возвращает
  // фактически действующий active — свой или чужой. Нужен для одновременного старта
  // нескольких реплик на пустой БД, где простой insertActive упал бы по unique.
  ensureActive(key: StoredSigningKey): Promise<StoredSigningKey>;
  // Ротация: все active → retired (retiredAt=at), затем вставка нового active.
  // Должна быть атомарной, чтобы не оставалось двух active одновременно.
  // Возвращает kid ключей, отправленных в retired.
  rotate(newActive: StoredSigningKey, at: Date): Promise<string[]>;
  // Аварийный отзыв ключа по kid (revoked_at=at). Идемпотентен. На старте
  // отозванные ключи выпадают из набора верификации.
  revoke(kid: string, at: Date): Promise<void>;
}
