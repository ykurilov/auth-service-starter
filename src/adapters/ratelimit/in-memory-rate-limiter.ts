import type { Clock } from '../../ports/clock.js';
import type {
  RateLimiter,
  RateLimitResult,
} from '../../ports/rate-limiter.js';

interface Window {
  count: number;
  windowStart: number;
  expiresAt: number;
}

// Периодичность фоновой очистки истёкших окон. Карта окон растёт с каждым
// уникальным ключом (ip+email и т.п.); без очистки long-running процесс без
// Redis накапливал бы окна бесконечно (утечка памяти). Таймер unref'нут —
// он не держит event loop и не мешает завершению процесса.
const DEFAULT_SWEEP_INTERVAL_MS = 60_000;

export class InMemoryRateLimiter implements RateLimiter {
  private readonly windows = new Map<string, Window>();
  private readonly sweepTimer: ReturnType<typeof setInterval>;

  constructor(
    private readonly clock: Clock,
    sweepIntervalMs: number = DEFAULT_SWEEP_INTERVAL_MS,
  ) {
    this.sweepTimer = setInterval(() => this.sweep(), sweepIntervalMs);
    // unref: таймер не должен удерживать процесс живым (важно для graceful
    // shutdown и для тестов, которые иначе висли бы на открытом хендле).
    this.sweepTimer.unref();
  }

  async hit(
    key: string,
    limit: number,
    windowSeconds: number,
  ): Promise<RateLimitResult> {
    const now = this.clock.now().getTime();
    const windowMs = windowSeconds * 1000;
    let w = this.windows.get(key);

    if (!w || now >= w.expiresAt) {
      w = { count: 1, windowStart: now, expiresAt: now + windowMs };
      this.windows.set(key, w);
    } else {
      w.count++;
    }

    const allowed = w.count <= limit;
    const remaining = Math.max(0, limit - w.count);
    const retryAfterSeconds = allowed ? 0 : Math.ceil((w.expiresAt - now) / 1000);

    return { allowed, remaining, retryAfterSeconds };
  }

  async refund(key: string): Promise<void> {
    const w = this.windows.get(key);
    if (w && this.clock.now().getTime() < w.expiresAt && w.count > 0) w.count--;
  }

  // Число отслеживаемых ключей — для наблюдаемости/метрик и проверки в тестах.
  get trackedKeys(): number {
    return this.windows.size;
  }

  // Удаляет окна, срок которых уже истёк: к таким ключам либо больше не
  // обращаются, либо следующий hit всё равно создаст окно заново.
  sweep(): void {
    const now = this.clock.now().getTime();
    for (const [key, w] of this.windows) {
      if (now >= w.expiresAt) this.windows.delete(key);
    }
  }

  async close(): Promise<void> {
    clearInterval(this.sweepTimer);
    this.windows.clear();
  }
}
