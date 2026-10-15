import type { FastifyInstance } from 'fastify';
import type { HttpDeps } from '../deps.js';
import { profileForScope } from '../../../domain/tokens/scope.js';

export function registerUserinfo(app: FastifyInstance, deps: HttpDeps): void {
  app.get('/userinfo', async (req, reply) => {
    const auth = req.headers['authorization'];
    const token =
      typeof auth === 'string' && auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) {
      reply.header('www-authenticate', 'Bearer');
      return reply.status(401).send({ error: 'invalid_token' });
    }
    let sub: string;
    let scope: string;
    try {
      const claims = await deps.tokens.verifyAccessToken(token);
      sub = claims.sub;
      scope = claims.scope;
    } catch {
      reply.header('www-authenticate', 'Bearer');
      return reply.status(401).send({ error: 'invalid_token' });
    }
    const user = await deps.identity.findUserById(sub);
    const emails = await deps.identity.findEmailsForUser(sub);
    const primary = emails.find((e) => e.verified) ?? emails[0];
    // sub возвращается всегда; name/email — только если покрыты scope токена
    // (OIDC Core 5.4). Поля вне scope в ответ не попадают.
    const scoped = profileForScope(
      { name: user?.displayName, email: primary?.email, emailVerified: primary?.verified },
      scope,
    );
    return reply.status(200).send({
      sub,
      ...(scoped.name !== undefined ? { name: scoped.name } : {}),
      ...(scoped.email !== undefined ? { email: scoped.email } : {}),
      ...(scoped.emailVerified !== undefined
        ? { email_verified: scoped.emailVerified }
        : {}),
    });
  });
}
