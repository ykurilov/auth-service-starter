import { describe, it, expect } from 'vitest';
import { advanceableClock } from '../../helpers/advanceable-clock.js';
import { InMemoryRateLimiter } from '../../../src/adapters/ratelimit/in-memory-rate-limiter.js';

describe('InMemoryRateLimiter', () => {
  it('разрешает первые limit попыток, remaining убывает до 0', async () => {
    const clock = advanceableClock(new Date('2026-07-02T00:00:00Z'));
    const limiter = new InMemoryRateLimiter(clock);

    const r1 = await limiter.hit('k', 3, 60);
    expect(r1.allowed).toBe(true);
    expect(r1.remaining).toBe(2);
    expect(r1.retryAfterSeconds).toBe(0);

    const r2 = await limiter.hit('k', 3, 60);
    expect(r2.allowed).toBe(true);
    expect(r2.remaining).toBe(1);

    const r3 = await limiter.hit('k', 3, 60);
    expect(r3.allowed).toBe(true);
    expect(r3.remaining).toBe(0);
  });

  it('(limit+1)-я попытка блокируется с retryAfterSeconds>0', async () => {
    const clock = advanceableClock(new Date('2026-07-02T00:00:00Z'));
    const limiter = new InMemoryRateLimiter(clock);

    for (let i = 0; i < 3; i++) await limiter.hit('k', 3, 60);

    const blocked = await limiter.hit('k', 3, 60);
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('после истечения окна счётчик сбрасывается', async () => {
    const clock = advanceableClock(new Date('2026-07-02T00:00:00Z'));
    const limiter = new InMemoryRateLimiter(clock);

    for (let i = 0; i < 3; i++) await limiter.hit('k', 3, 60);
    expect((await limiter.hit('k', 3, 60)).allowed).toBe(false);

    clock.advance(60);

    const fresh = await limiter.hit('k', 3, 60);
    expect(fresh.allowed).toBe(true);
    expect(fresh.remaining).toBe(2);
  });

  it('refund возвращает одно списание в живом окне (P3-7)', async () => {
    const clock = { now: () => new Date('2026-07-01T00:00:00Z') };
    const limiter = new InMemoryRateLimiter(clock);
    await limiter.hit('k', 1, 60);
    await limiter.refund('k');
    expect((await limiter.hit('k', 1, 60)).allowed).toBe(true);
    expect((await limiter.hit('k', 1, 60)).allowed).toBe(false);
    await limiter.close();
  });

  it('разные ключи независимы', async () => {
    const clock = advanceableClock(new Date('2026-07-02T00:00:00Z'));
    const limiter = new InMemoryRateLimiter(clock);

    for (let i = 0; i < 3; i++) await limiter.hit('a', 3, 60);
    expect((await limiter.hit('a', 3, 60)).allowed).toBe(false);

    const b = await limiter.hit('b', 3, 60);
    expect(b.allowed).toBe(true);
    expect(b.remaining).toBe(2);
  });

  it('sweep удаляет истёкшие окна, живые оставляет (нет утечки памяти)', async () => {
    const clock = advanceableClock(new Date('2026-07-02T00:00:00Z'));
    const limiter = new InMemoryRateLimiter(clock);

    await limiter.hit('short', 3, 60); // окно 60с
    await limiter.hit('long', 3, 600); // окно 600с
    expect(limiter.trackedKeys).toBe(2);

    clock.advance(120); // 'short' истёк, 'long' ещё жив
    limiter.sweep();

    expect(limiter.trackedKeys).toBe(1);
    // Живое окно не тронуто: счётчик продолжается, а не сбрасывается.
    const r = await limiter.hit('long', 3, 600);
    expect(r.remaining).toBe(1);
  });

  it('sweep не держит процесс: close останавливает таймер очистки', async () => {
    const clock = advanceableClock(new Date('2026-07-02T00:00:00Z'));
    const limiter = new InMemoryRateLimiter(clock);
    await limiter.hit('k', 3, 60);
    await limiter.close();
    expect(limiter.trackedKeys).toBe(0);
  });
});
