import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { HttpDeps } from '../deps.js';
import { ipHash } from '../rate-limit.js';

const bodySchema = z.object({ token: z.string().min(1) }).passthrough();

// RFC 7009. Поддерживаем refresh-токены (access — короткоживущий JWT, его не
// отзываем). Ответ всегда 200 — узнать по ответу, существовал ли токен, нельзя.
export function registerRevoke(app: FastifyInstance, deps: HttpDeps): void {
  app.post('/oauth/revoke', async (req, reply) => {
    reply.header('cache-control', 'no-store');
    const rule = deps.config.rateLimits.revoke;
    const rl = await deps.rateLimiter.hit(`revoke:${ipHash(req)}`, rule.limit, rule.windowSeconds);
    if (!rl.allowed) {
      reply.header('Retry-After', String(rl.retryAfterSeconds));
      return reply.status(429).send({ error: 'too_many_requests' });
    }
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success) return reply.status(400).send({ error: 'invalid_request' });
    await deps.sessions.revokeByRefreshToken(parsed.data.token);
    return reply.status(200).send();
  });
}
