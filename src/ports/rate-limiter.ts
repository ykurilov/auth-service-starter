export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

export interface RateLimiter {
  hit(
    key: string,
    limit: number,
    windowSeconds: number,
  ): Promise<RateLimitResult>;
  // Освобождает удерживаемые ресурсы (сетевые соединения) при graceful
  // shutdown. Реализациям без ресурсов достаточно no-op.
  close(): Promise<void>;
}
