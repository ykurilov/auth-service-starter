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
  // Возвращает одно списание по ключу в живом окне (действие не состоялось
  // не по вине пользователя, например почтовый провайдер отказал). Нужен
  // лимитерам отправки кода (Postgres, процесс); у прочих может не быть.
  refund?(key: string): Promise<void>;
  // Освобождает удерживаемые ресурсы (сетевые соединения) при graceful
  // shutdown. Реализациям без ресурсов достаточно no-op.
  close(): Promise<void>;
}
