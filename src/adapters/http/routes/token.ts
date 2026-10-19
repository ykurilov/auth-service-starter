import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { HttpDeps } from '../deps.js';
import { oauthErrorFor } from '../oauth-errors.js';
import { ipHash } from '../rate-limit.js';
import { logSecurityEvent } from '../security-log.js';
import type { IssuedTokens } from '../../../domain/sessions/session-service.js';
import type { DeviceInfo } from '../../../domain/sessions/device.js';
import { InvalidGrantError } from '../../../domain/login/errors.js';
import { grantFitsClient } from '../../../domain/login/grant-policy.js';
import { sha256Hex } from '../../../domain/shared/hash.js';
import { RefreshTokenReuseError } from '../../../domain/sessions/errors.js';
import { chainOfLogin } from '../../../domain/sso/sso-session-service.js';
import type { Client } from '../../../domain/clients/client.js';

function device(req: FastifyRequest): DeviceInfo {
  const ua = req.headers['user-agent'];
  return { userAgent: Array.isArray(ua) ? ua[0] : ua, ip: req.ip };
}
function toJson(t: IssuedTokens) {
  return {
    access_token: t.accessToken,
    id_token: t.idToken,
    refresh_token: t.refreshToken,
    token_type: 'Bearer',
    expires_in: t.expiresIn,
    scope: t.scope,
  };
}

const bodySchema = z.object({ grant_type: z.string() }).passthrough();
const codeSchema = z.object({
  code: z.string(),
  redirect_uri: z.string(),
  client_id: z.string(),
  code_verifier: z.string(),
});
const refreshSchema = z.object({ refresh_token: z.string(), client_id: z.string().optional() });

function allowsProvider(client: Client | null, provider: string): client is Client {
  return client !== null && client.allowedProviders.includes(provider);
}

export function registerToken(app: FastifyInstance, deps: HttpDeps): void {
  // Client IDs in requests are public and cannot identify a rate-limit principal.
  const hitPrincipal = (key: string) => deps.rateLimiter.hit(key, 60, 900);
  const tooManyRequests = (reply: FastifyReply, retryAfterSeconds: number) => {
    reply.header('Retry-After', String(retryAfterSeconds));
    return reply.status(429).send({ error: 'too_many_requests' });
  };

  app.post('/oauth/token', async (req, reply) => {
    reply.header('cache-control', 'no-store');
    // Token-эндпоинт отвечает JSON (не HTML), поэтому лимит применяем здесь
    // напрямую: 429 с Retry-After и телом в стиле OAuth-ошибок.
    // This is a WIDE configurable abuse budget (10000/15min by default), shared by the
    // backend IP. Narrow limits below use only authenticated session/grant IDs.
    // req.ip respects the server's configured proxy hops, never raw XFF.
    const rule = deps.config.rateLimits.token;
    const rl = await deps.rateLimiter.hit(`token:${ipHash(req)}`, rule.limit, rule.windowSeconds);
    if (!rl.allowed) return tooManyRequests(reply, rl.retryAfterSeconds);
    const base = bodySchema.safeParse(req.body);
    if (!base.success) return reply.status(400).send({ error: 'invalid_request' });
    try {
      if (base.data.grant_type === 'authorization_code') {
        const b = codeSchema.parse(req.body);
        const redeem = {
          code: b.code,
          clientId: b.client_id,
          redirectUri: b.redirect_uri,
          codeVerifier: b.code_verifier,
        };
        // Лимит пользователя — до блокировки клиента и транзакции: зависший
        // лимитер (Redis) не держит ни соединение пула, ни блокировку. Пользователя
        // берём из кода, не гася его: при отказе по лимиту код остаётся живым.
        const preview = await deps.codes.inspect(redeem);
        const limit = await hitPrincipal(
          `token-user:${sha256Hex(JSON.stringify([preview.clientId, preview.userId]))}`);
        if (!limit.allowed) return tooManyRequests(reply, limit.retryAfterSeconds);
        // Гашение кода, проверка политики и создание сессии — под общей
        // блокировкой клиента: PATCH или DELETE клиента либо дождётся конца
        // обмена и отзовёт его сессию, либо обмен увидит уже новую политику.
        // Ответ отправляем после фиксации транзакции.
        const issued = await deps.clientLock.shared(b.client_id, async ({ client, codes, sessions, sso }) => {
          const grant = await codes.redeem(redeem);
          // Отказ по политике — без исключения: погашенный код фиксируется.
          if (!grantFitsClient(client, grant, b.redirect_uri)) return null;
          // Сессия запоминает SSO-цепочку браузера, через которую выдан код:
          // смена аккаунта и выход в этом браузере её погасят.
          const ssoChainId = await chainOfLogin(sso, grant.auth.loginId);
          const started = await sessions.start({
            userId: grant.userId,
            clientId: grant.clientId,
            provider: grant.auth.provider,
            profile: {
              email: grant.auth.email,
              emailVerified: grant.auth.emailVerified,
              name: grant.auth.name,
            },
            scope: grant.scope,
            device: device(req),
            nonce: grant.nonce,
            ...(ssoChainId ? { ssoChainId } : {}),
          });
          // Цепочку перепроверяем после записи сессии, удерживая SSO-сессии
          // пользователя в ней до конца транзакции. Выход или смена аккаунта
          // в браузере либо дождутся транзакции и погасят новую сессию вместе
          // с цепочкой, либо уже погасили цепочку — тогда гасим сессию здесь.
          // Повторный вход того же пользователя цепочку не обрывает.
          if (ssoChainId && !(await sso.holdSignedIn(ssoChainId, grant.userId))) {
            await sessions.revoke(started.sessionId);
            return null;
          }
          return started;
        });
        if (!issued) throw new InvalidGrantError();
        return reply.status(200).send(toJson(issued));
      }
      if (base.data.grant_type === 'refresh_token') {
        const b = refreshSchema.parse(req.body);
        // Сессия по токену — только ключ лимита; лимит — до блокировки клиента.
        const session = await deps.sessions.resolveRefreshSession(b.refresh_token);
        const limit = await hitPrincipal(`token-session:${session.id}`);
        if (!limit.allowed) return tooManyRequests(reply, limit.retryAfterSeconds);
        if (b.client_id !== undefined && b.client_id !== session.clientId) throw new InvalidGrantError();
        // Проверка политики и выпуск токенов — под общей блокировкой клиента,
        // как обмен кода: PATCH, запретивший провайдера, либо дождётся конца
        // refresh и отзовёт сессию, либо refresh увидит уже новую политику.
        // Повтор погашенного токена отзывает сессию; отзыв фиксируется вместе
        // с транзакцией, поэтому ошибку бросаем уже после неё.
        const outcome = await deps.clientLock.shared(session.clientId, async ({ client, sessions }) => {
          if (!allowsProvider(client, session.provider)) return { error: new InvalidGrantError() };
          try {
            return { issued: await sessions.refresh(b.refresh_token, device(req)) };
          } catch (err) {
            if (err instanceof RefreshTokenReuseError) return { error: err };
            throw err;
          }
        });
        if ('error' in outcome) throw outcome.error;
        return reply.status(200).send(toJson(outcome.issued));
      }
      return reply.status(400).send({ error: 'unsupported_grant_type' });
    } catch (err) {
      if (err instanceof RefreshTokenReuseError) {
        logSecurityEvent(deps.logger, req, 'refresh_token_reuse');
      }
      const known = oauthErrorFor(err);
      if (!known) throw err; // инфраструктурный сбой -> глобальный errorHandler: 500 + лог
      return reply.status(known.status).send({ error: known.error });
    }
  });
}
