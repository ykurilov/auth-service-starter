import { describe, it, expect } from 'vitest';
import { Redis } from 'ioredis';
import { RedisRateLimiter } from '../../../src/adapters/ratelimit/redis-rate-limiter.js';
import { InMemoryRateLimiter } from '../../../src/adapters/ratelimit/in-memory-rate-limiter.js';
import { fakeClock } from '../../helpers/fake-clock.js';

const REDIS_URL = process.env.REDIS_URL_TEST;

describe('RedisRateLimiter fail-open (без реального Redis)', () => {
  it('сбой Redis → запрос пропущен, onUnavailable вызван', async () => {
    const calls: Error[] = [];
    const broken = {
      eval: async () => {
        throw new Error('connection is closed');
      },
    };
    const limiter = new RedisRateLimiter(broken as never, (err) => calls.push(err));
    const res = await limiter.hit('k', 5, 60);
    expect(res.allowed).toBe(true);
    expect(res.retryAfterSeconds).toBe(0);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.message).toBe('connection is closed');
  });

  it('сбой Redis с резервным лимитером → лимит продолжает действовать (не fail-open)', async () => {
    const broken = {
      eval: async () => {
        throw new Error('connection is closed');
      },
    };
    const fallback = new InMemoryRateLimiter(fakeClock(new Date('2026-07-01T00:00:00Z')));
    const limiter = new RedisRateLimiter(broken as never, undefined, fallback);
    const allowed = [];
    for (let i = 0; i < 4; i++) allowed.push((await limiter.hit('k', 3, 60)).allowed);
    expect(allowed).toEqual([true, true, true, false]);
    await fallback.close();
  });

  it('close на мёртвом соединении не бросает (quit падает → disconnect)', async () => {
    let disconnected = false;
    const broken = {
      eval: async () => {
        throw new Error('down');
      },
      quit: async () => {
        throw new Error('closed');
      },
      disconnect: () => {
        disconnected = true;
      },
    };
    const limiter = new RedisRateLimiter(broken as never);
    await expect(limiter.close()).resolves.toBeUndefined();
    expect(disconnected).toBe(true);
  });
});

describe.skipIf(!REDIS_URL)('RedisRateLimiter', () => {
  it('блокирует после превышения лимита и выставляет TTL', async () => {
    const redis = new Redis(REDIS_URL as string);
    const key = `test:ratelimit:${Date.now()}:${Math.random()}`;

    try {
      const limiter = new RedisRateLimiter(redis);

      const r1 = await limiter.hit(key, 2, 60);
      expect(r1.allowed).toBe(true);
      expect(r1.remaining).toBe(1);

      const r2 = await limiter.hit(key, 2, 60);
      expect(r2.allowed).toBe(true);
      expect(r2.remaining).toBe(0);

      const r3 = await limiter.hit(key, 2, 60);
      expect(r3.allowed).toBe(false);
      expect(r3.remaining).toBe(0);
      expect(r3.retryAfterSeconds).toBeGreaterThan(0);

      const ttl = await redis.ttl(key);
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(60);
    } finally {
      await redis.del(key);
      await redis.quit();
    }
  });
});
