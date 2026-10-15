import { timingSafeEqual } from 'node:crypto';

// Проверка bearer-токена Admin API в постоянное время. Пустой expected → всегда
// отказ (Admin API считается выключенным без настроенного токена).
export function checkAdminAuth(authHeader: string | undefined, expected: string): boolean {
  if (!expected) return false;
  if (typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) return false;
  const presented = authHeader.slice(7);
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
