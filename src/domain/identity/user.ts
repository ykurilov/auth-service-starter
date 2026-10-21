// Блокировки пользователей сервис не поддерживает: ни при входе, ни при
// обновлении токена статус не проверяется. Колонка users.status в базе есть,
// но всегда 'active'.
export type UserStatus = 'active';

export interface User {
  id: string;
  displayName?: string;
  status: UserStatus;
  createdAt: Date;
}

export interface Identity {
  id: string;
  userId: string;
  provider: string;
  subject: string;
  createdAt: Date;
}

export interface EmailAddress {
  id: string;
  userId: string;
  email: string;
  verified: boolean;
  createdAt: Date;
}

export function normalizeEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

// Строгий разбор адреса почты для входа: только ASCII addr-spec без
// отображаемого имени, комментариев, кавычек, пробелов и списков. Иначе строка
// вида "boss@x.ru <attacker@y.ru>" ушла бы в почтовый сервис как получатель и
// стала бы «подтверждённым» email в токенах. null — адрес не принимается.
const LOCAL_PART = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function parseEmailAddress(raw: string): string | null {
  const email = normalizeEmail(raw);
  if (email.length === 0 || email.length > 254) return null;
  const at = email.lastIndexOf('@');
  if (at <= 0 || at !== email.indexOf('@')) return null;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length > 64 || !LOCAL_PART.test(local)) return null;
  const labels = domain.split('.');
  if (labels.length < 2) return null;
  if (!labels.every((l) => DOMAIN_LABEL.test(l))) return null;
  // Домен верхнего уровня — буквы (исключает голые IP вида 1.2.3.4).
  if (!/^[a-z]{2,63}$/.test(labels[labels.length - 1]!) && !/^xn--[a-z0-9-]+$/.test(labels[labels.length - 1]!)) return null;
  return email;
}
