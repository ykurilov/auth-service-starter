import type { Db } from '../db/pool.js';
import type { Clock } from '../../ports/clock.js';
import type { RateLimiter, RateLimitResult } from '../../ports/rate-limiter.js';
import { sha256Hex } from '../../domain/shared/hash.js';

// Лимитер на Postgres для чувствительных к перебору операций (коды из письма).
// Счётчик — одна строка на ключ, обновляется одним upsert: Postgres сам
// сериализует конкурентные hit одной строки, поэтому лимит общий для всех
// экземпляров сервиса и переживает перезапуск. Redis здесь не участвует —
// его сбой не ослабляет защиту кодов. Ошибка БД пробрасывается (fail-closed):
// без БД вход по коду всё равно невозможен.
export class PgRateLimiter implements RateLimiter {
  constructor(
    private readonly db: Db,
    private readonly clock: Clock,
  ) {}

  async hit(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult> {
    const now = this.clock.now();
    const windowEnd = new Date(now.getTime() + windowSeconds * 1000);
    const { rows } = await this.db.query<{ count: number; expires_at: Date }>(
      `insert into rate_limit_counters (key_hash, count, expires_at) values ($1, 1, $3)
       on conflict (key_hash) do update set
         count = case when rate_limit_counters.expires_at <= $2 then 1
                      else rate_limit_counters.count + 1 end,
         expires_at = case when rate_limit_counters.expires_at <= $2 then $3
                           else rate_limit_counters.expires_at end
       returning count, expires_at`,
      [sha256Hex(`rl:${key}`), now, windowEnd],
    );
    const count = Number(rows[0]!.count);
    const expiresAt = new Date(rows[0]!.expires_at);
    const allowed = count <= limit;
    return {
      allowed,
      remaining: Math.max(0, limit - count),
      retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil((expiresAt.getTime() - now.getTime()) / 1000)),
    };
  }

  async deleteExpired(before: Date): Promise<number> {
    const { rowCount } = await this.db.query(
      'delete from rate_limit_counters where expires_at < $1',
      [before],
    );
    return rowCount;
  }

  async close(): Promise<void> {
    // Пулом владеет bootstrap.
  }
}
