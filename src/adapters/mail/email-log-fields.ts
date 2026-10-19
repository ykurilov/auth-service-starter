import type { OutgoingEmail } from '../../ports/mailer.js';
import { sha256Hex } from '../../domain/shared/hash.js';
import { normalizeEmail } from '../../domain/identity/user.js';

// Что о письме можно писать в журнал: тип и хеш адреса, как в security-log.
// Тема и тело содержат код входа, адрес — персональные данные.
export function emailLogFields(email: OutgoingEmail): { kind?: string; toHash: string } {
  return {
    ...(email.kind ? { kind: email.kind } : {}),
    toHash: sha256Hex(normalizeEmail(email.to)),
  };
}
