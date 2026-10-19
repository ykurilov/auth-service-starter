import { createHmac, randomBytes } from 'node:crypto';

// В хранилище — только SHA-256-хеш этого значения (см. shared/hash).
export function generateRefreshToken(): string {
  return randomBytes(32).toString('base64url');
}

// Семейство — общая первая часть всех refresh-токенов одной цепочки ротаций:
// «<семейство>.<секрет>». Само по себе права не даёт. Очистка удаляет строки
// давно погашенных токенов, а по семейству предъявленный токен всё равно
// находит свою сессию: повтор такого токена отзывает её, как и раньше.
// В хранилище — только хеш семейства. Токены прежнего формата — без точки.
export function generateRefreshFamily(): string {
  return randomBytes(16).toString('base64url');
}

const FAMILY_TOKEN = /^([A-Za-z0-9_-]{22})\.[A-Za-z0-9_-]+$/;

export function refreshFamilyOf(rawToken: string): string | null {
  return FAMILY_TOKEN.exec(rawToken)?.[1] ?? null;
}

export type RefreshDerivation = 'hmac-sha256-v1' | 'hmac-sha256-v2';

const hmac = (key: string, label: string) => createHmac('sha256', key).update(label);

// Parent secret is the HMAC key; database hashes cannot recover descendants.
// v2 carries the parent's family; a parent of the old format gets one derived
// from its own secret, so a retry within grace re-derives the same successor.
export function deriveRefreshToken(
  parentSecret: string,
  successorId: string,
  version: RefreshDerivation = 'hmac-sha256-v2',
): string {
  if (version === 'hmac-sha256-v1') {
    return hmac(parentSecret, `auth-v3:refresh:hmac-sha256-v1:${successorId}`).digest('base64url');
  }
  const family = refreshFamilyOf(parentSecret) ??
    hmac(parentSecret, `auth-v3:refresh:family-v2:${successorId}`).digest().subarray(0, 16).toString('base64url');
  return `${family}.${hmac(parentSecret, `auth-v3:refresh:hmac-sha256-v2:${successorId}`).digest('base64url')}`;
}

// История ротаций, которую хранит очистка: токены, погашенные за последний
// час (с большим запасом длиннее окна grace — повтор в нём восстанавливает
// цепочку по этим строкам), последние REFRESH_HISTORY_KEEP_LATEST токенов
// сессии и самый новый токен каждого семейства (по нему семейство находит
// сессию). Строки токенов прежнего формата, без семейства, не удаляются: их
// повтор узнаётся только по строке. Новых таких не появляется.
//
// Строк на сессию при очистке раз в час: у давно не обновлявшейся — 3; у
// клиента, обновляющего токен раз в срок access (15 минут), — до 4 за час
// окна и до 4 за час между очистками, то есть не больше 9; предел refresh
// по сессии (60 за 15 минут) даёт не больше 2 × 240 + 1 = 481.
export const REFRESH_HISTORY_RETENTION_MS = 3600 * 1000;
export const REFRESH_HISTORY_KEEP_LATEST = 3;

export interface RefreshTokenRecord {
  id: string;
  sessionId: string;
  tokenHash: string;             // sha256Hex(raw)
  previousTokenId: string | null; // предшественник в цепочке
  replacedById: string | null;    // преемник (проставляется при гашении)
  createdAt: Date;
  consumedAt: Date | null;
  derivationVersion?: RefreshDerivation; // absent on random tokens
  familyHash?: string;           // sha256Hex(семейство); нет у токенов прежнего формата
}

export interface RefreshTokenStore {
  // Atomic CAS + successor publication. Failure leaves both records unchanged.
  rotate(headId: string, successor: RefreshTokenRecord, at: Date): Promise<boolean>;
  save(record: RefreshTokenRecord): Promise<void>;
  findByHash(tokenHash: string): Promise<RefreshTokenRecord | null>;
  findById(id: string): Promise<RefreshTokenRecord | null>;
  // Сессия, чьи токены несут это семейство (по хешу), или null.
  findSessionIdByFamily(familyHash: string): Promise<string | null>;
  // CAS: пометить consumed + проставить replacedById, только если ещё не погашен.
  // true — этот вызов реально погасил (выиграл гонку).
  consume(id: string, replacedById: string, at: Date): Promise<boolean>;
  // Удаляет токены с семейством, погашенные раньше consumedBefore, кроме
  // keepLatest последних токенов сессии и самого нового токена семейства.
  // Возвращает число удалённых.
  pruneHistory(consumedBefore: Date, keepLatest: number): Promise<number>;
}
