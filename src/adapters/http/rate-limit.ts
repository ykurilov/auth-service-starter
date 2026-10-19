import type { FastifyReply, FastifyRequest } from 'fastify';
import type { HttpDeps } from './deps.js';
import type { RateLimiter } from '../../ports/rate-limiter.js';
import { sha256Hex } from '../../domain/shared/hash.js';
import { errorPage } from './views/error-page.js';

// Хешируем ip перед использованием в ключе лимитера: сам ключ (и его возможные
// логи/хранилище) не должны содержать сырой адрес пользователя.
export function ipHash(req: FastifyRequest): string {
  return sha256Hex(req.ip);
}

// Время ожидания для человека: «через 42 с», «через 15 мин», «через 3 ч».
// До полутора минут — в секундах: «через 1 мин» вместо «через 60 с» звучит
// дольше, чем есть.
export function waitText(seconds: number): string {
  if (seconds <= 90) return `через ${Math.max(1, Math.ceil(seconds))} с`;
  const minutes = Math.ceil(seconds / 60);
  if (minutes <= 90) return `через ${minutes} мин`;
  return `через ${Math.ceil(minutes / 60)} ч`;
}

// Отказ по лимиту: 429 + Retry-After и страница со временем ожидания.
export function sendTooManyAttempts(reply: FastifyReply, retryAfterSeconds: number): void {
  reply.header('Retry-After', String(retryAfterSeconds));
  reply.status(429);
  reply.type('text/html; charset=utf-8');
  reply.send(errorPage(
    'Слишком много попыток',
    `Повторить можно ${waitText(retryAfterSeconds)}. Вернитесь на страницу входа и попробуйте снова.`,
  ));
}

// enforce возвращает true если запрос можно продолжать, false если лимит
// превышен. В последнем случае сам ставит 429 + Retry-After + рендерит
// страницу со временем ожидания — обработчику остаётся только `return`.
export async function enforce(
  deps: HttpDeps,
  reply: FastifyReply,
  key: string,
  rule: { limit: number; windowSeconds: number },
  limiter: RateLimiter = deps.rateLimiter,
): Promise<boolean> {
  const r = await limiter.hit(key, rule.limit, rule.windowSeconds);
  if (!r.allowed) {
    sendTooManyAttempts(reply, r.retryAfterSeconds);
    return false;
  }
  return true;
}
