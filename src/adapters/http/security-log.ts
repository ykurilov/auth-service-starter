import type { FastifyRequest } from 'fastify';
import type { Logger } from 'pino';
import { sha256Hex } from '../../domain/shared/hash.js';
import { normalizeEmail } from '../../domain/identity/user.js';
import { ipHash } from './rate-limit.js';

// События безопасности пишем структурированно и только в хэшах: по логам можно
// расследовать инцидент (сопоставить попытки), не раскладывая в них персональные
// данные и секреты.
export function logSecurityEvent(
  logger: Logger,
  req: FastifyRequest,
  event: 'login_failed' | 'refresh_token_reuse',
  extra: { method?: string; email?: string } = {},
): void {
  logger.warn(
    {
      event,
      ...(extra.method !== undefined ? { method: extra.method } : {}),
      ...(extra.email !== undefined ? { emailHash: sha256Hex(normalizeEmail(extra.email)) } : {}),
      ipHash: ipHash(req),
    },
    'событие безопасности',
  );
}
