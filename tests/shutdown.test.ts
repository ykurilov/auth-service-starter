import { describe, it, expect, vi } from 'vitest';
import { shutdownGracefully, shutdownWithTimeout } from '../src/index.js';

describe('shutdownGracefully', () => {
  it('закрывает app, затем db', async () => {
    const order: string[] = [];
    const app = {
      close: vi.fn(async () => {
        order.push('app');
      }),
    };
    const db = {
      close: vi.fn(async () => {
        order.push('db');
      }),
    };
    await shutdownGracefully(app as never, db as never);
    expect(order).toEqual(['app', 'db']);
  });

  it('без db закрывает только app', async () => {
    const app = { close: vi.fn(async () => {}) };
    await expect(shutdownGracefully(app as never, undefined)).resolves.toBeUndefined();
    expect(app.close).toHaveBeenCalled();
  });

  it('закрывает и rateLimiter после db, его ошибка не пробрасывается', async () => {
    const order: string[] = [];
    const app = {
      close: vi.fn(async () => {
        order.push('app');
      }),
    };
    const db = {
      close: vi.fn(async () => {
        order.push('db');
      }),
    };
    const limiter = {
      close: vi.fn(async () => {
        order.push('limiter');
        throw new Error('redis dead');
      }),
    };
    await expect(
      shutdownGracefully(app as never, db as never, limiter),
    ).resolves.toBeUndefined();
    expect(order).toEqual(['app', 'db', 'limiter']);
  });

  it('ошибка close не пробрасывается (db всё равно закрывается)', async () => {
    const order: string[] = [];
    const app = {
      close: vi.fn(async () => {
        throw new Error('x');
      }),
    };
    const db = {
      close: vi.fn(async () => {
        order.push('db');
      }),
    };
    await expect(shutdownGracefully(app as never, db as never)).resolves.toBeUndefined();
    expect(order).toEqual(['db']);
  });
});

describe('shutdownWithTimeout', () => {
  it('успевает до таймаута → ok', async () => {
    const app = { close: vi.fn(async () => {}) };
    const db = { close: vi.fn(async () => {}) };
    await expect(shutdownWithTimeout(app as never, db as never, 1000)).resolves.toBe('ok');
    expect(app.close).toHaveBeenCalled();
    expect(db.close).toHaveBeenCalled();
  });

  it('зависший close → timeout, не висит и не reject', async () => {
    const app = {
      close: vi.fn(() => new Promise<void>((resolve) => setTimeout(resolve, 1000))),
    };
    await expect(shutdownWithTimeout(app as never, undefined, 20)).resolves.toBe('timeout');
  });
});
