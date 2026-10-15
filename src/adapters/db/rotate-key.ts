import type { Db } from './pool.js';
import { PgSigningKeyStore } from '../repository/pg/pg-signing-key-store.js';
import { generateSigningKeyPem } from '../../domain/tokens/signing-key.js';

export interface RotateResult {
  newKid: string;
  // kid прежних active-ключей: их передают в revoke-key при утечке.
  retiredKids: string[];
}

// Генерирует новую пару, делает её active, прежние active → retired
// (атомарно внутри store.rotate). now передаётся аргументом ради
// тестируемости (в CLI — new Date()).
export async function runRotate(db: Db, now: Date): Promise<RotateResult> {
  const store = new PgSigningKeyStore(db);
  const gen = await generateSigningKeyPem();
  const retiredKids = await store.rotate(
    { ...gen, status: 'active', createdAt: now, retiredAt: null, revokedAt: null },
    now,
  );
  return { newKid: gen.kid, retiredKids };
}

// Строка отчёта rotate-key для оператора.
export function describeRotation(result: RotateResult): string {
  const retired = result.retiredKids.length ? result.retiredKids.join(', ') : 'нет';
  return `Новый активный ключ: ${result.newKid}; отправлены в retired: ${retired}`;
}

// Аварийный отзыв скомпрометированного ключа: помечает его revoked_at, после
// чего на следующем старте сервис исключит ключ из набора верификации, и все
// токены, подписанные им, станут невалидны. Отзывать можно только не-active
// ключ: сначала ротация (новый active), затем отзыв прежнего — иначе сервис
// остался бы без ключа для проверки собственных свежих токенов.
export async function runRevoke(db: Db, kid: string, now: Date): Promise<void> {
  const store = new PgSigningKeyStore(db);
  const all = await store.listAll();
  const target = all.find((k) => k.kid === kid);
  if (!target) throw new Error(`ключ ${kid} не найден`);
  if (target.status === 'active') {
    throw new Error(
      `ключ ${kid} активен: сначала выполните ротацию (rotate-key), затем отзыв`,
    );
  }
  await store.revoke(kid, now);
}
