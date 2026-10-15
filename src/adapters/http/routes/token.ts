import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { HttpDeps } from '../deps.js';
import { oauthErrorFor } from '../oauth-errors.js';
import { ipHash } from '../rate-limit.js';
import { logSecurityEvent } from '../security-log.js';
import type { IssuedTokens } from '../../../domain/sessions/session-service.js';
import type { DeviceInfo } from '../../../domain/sessions/device.js';
import { InvalidGrantError } from '../../../domain/login/errors.js';
import { sha256Hex } from '../../../domain/shared/hash.js';
import { RefreshTokenReuseError } from '../../../domain/sessions/errors.js';

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

export function registerToken(app: FastifyInstance, deps: HttpDeps): void {
  // Client IDs in requests are public and cannot identify a rate-limit principal.
  const allowPrincipal = async (key: string, reply: FastifyReply) => {
    const rl = await deps.rateLimiter.hit(key, 60, 900);
    if (rl.allowed) return true;
    reply.header('Retry-After', String(rl.retryAfterSeconds));
    reply.status(429).send({ error: 'too_many_requests' });
    return false;
  };
  const checkPolicy = async (clientId: string, provider: string, redirectUri?: string) => {
    const client = await deps.clients.findClient(clientId);
    if (!client || !client.allowedProviders.includes(provider) ||
        (redirectUri !== undefined && !client.redirectUris.includes(redirectUri))) {
      throw new InvalidGrantError();
    }
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
    if (!rl.allowed) {
      reply.header('Retry-After', String(rl.retryAfterSeconds));
      return reply.status(429).send({ error: 'too_many_requests' });
    }
    const base = bodySchema.safeParse(req.body);
    if (!base.success) return reply.status(400).send({ error: 'invalid_request' });
    try {
      if (base.data.grant_type === 'authorization_code') {
        const b = codeSchema.parse(req.body);
        const grant = await deps.codes.redeem({
          code: b.code,
          clientId: b.client_id,
          redirectUri: b.redirect_uri,
          codeVerifier: b.code_verifier,
        });
        await checkPolicy(grant.clientId, grant.auth.provider, b.redirect_uri);
        if (!(await allowPrincipal(`token-user:${sha256Hex(JSON.stringify([grant.clientId, grant.userId]))}`, reply)))
          return reply;
        const issued = await deps.sessions.start({
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
        });
        return reply.status(200).send(toJson(issued));
      }
      if (base.data.grant_type === 'refresh_token') {
        const b = refreshSchema.parse(req.body);
        const session = await deps.sessions.resolveRefreshSession(b.refresh_token);
        await checkPolicy(session.clientId, session.provider);
        if (!(await allowPrincipal(`token-session:${session.id}`, reply))) return reply;
        if (b.client_id !== undefined && b.client_id !== session.clientId) throw new InvalidGrantError();
        const issued = await deps.sessions.refresh(b.refresh_token, device(req));
        return reply.status(200).send(toJson(issued));
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
