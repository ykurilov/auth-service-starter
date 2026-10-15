import { Redis } from 'ioredis';
import type {
  RateLimiter,
  RateLimitResult,
} from '../../ports/rate-limiter.js';

// INCR и EXPIRE выполняются атомарно в одном eval: иначе процесс, упавший между
// INCR и EXPIRE, оставил бы ключ без TTL навсегда (лимит завис бы бессрочно).
// Скрипт возвращает и счётчик, и TTL за один round-trip.
const HIT_LUA = `
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('TTL', KEYS[1])
return {c, ttl}
`;

export class RedisRateLimiter implements RateLimiter {
  constructor(
    private readonly redis: Redis,
    private readonly onUnavailable?: (err: Error) => void,
    // Резервный лимитер на время недоступности Redis (обычно in-memory этого
    // процесса): защита ослабевает до «на один экземпляр», но не исчезает.
    private readonly fallback?: RateLimiter,
  ) {}

  async hit(
    key: string,
    limit: number,
    windowSeconds: number,
  ): Promise<RateLimitResult> {
    try {
      const raw = (await this.redis.eval(
        HIT_LUA,
        1,
        key,
        String(windowSeconds),
      )) as [number | string, number | string];
      const count = Number(raw[0]);
      const ttl = Number(raw[1]);

      const allowed = count <= limit;
      const remaining = Math.max(0, limit - count);
      const retryAfterSeconds = allowed ? 0 : Math.max(0, ttl);

      return { allowed, remaining, retryAfterSeconds };
    } catch (err) {
      // Недоступный Redis не превращается в отказ всего входа и выдачи
      // токенов: считаем по резервному лимитеру процесса (ограничение остаётся,
      // просто не общее между экземплярами). Без резервного — fail-open.
      // Коды из письма Redis не используют вовсе (PgRateLimiter).
      this.onUnavailable?.(err as Error);
      if (this.fallback) return this.fallback.hit(key, limit, windowSeconds);
      return { allowed: true, remaining: limit, retryAfterSeconds: 0 };
    }
  }

  async close(): Promise<void> {
    await this.fallback?.close();
    try {
      // quit ждёт подтверждения от сервера; на мёртвом соединении не висим —
      // рвём сокет принудительно.
      await this.redis.quit();
    } catch {
      this.redis.disconnect();
    }
  }
}

export function createRedisRateLimiter(
  redisUrl: string,
  onUnavailable?: (err: Error) => void,
  fallback?: RateLimiter,
): RateLimiter {
  // Без offline queue и с короткими таймаутами: при обрыве Redis команды
  // падают сразу (и hit уходит в fail-open), а не копятся в очереди,
  // подвешивая каждый запрос до переподключения.
  const redis = new Redis(redisUrl, {
    connectTimeout: 2000,
    commandTimeout: 1000,
    enableOfflineQueue: false,
    maxRetriesPerRequest: 1,
  });
  // ioredis без обработчика 'error' роняет процесс необработанным событием.
  redis.on('error', (err) => onUnavailable?.(err));
  return new RedisRateLimiter(redis, onUnavailable, fallback);
}
