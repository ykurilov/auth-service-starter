import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { HttpDeps } from '../deps.js';
import { profileForScope } from '../../../domain/tokens/scope.js';

// Access token из запроса: заголовок Authorization: Bearer или (только POST)
// поле access_token формы (RFC 6750 §2.2). Оба способа сразу — ошибка запроса.
function bearerToken(req: FastifyRequest): string | null | 'ambiguous' {
  const auth = req.headers['authorization'];
  const fromHeader = typeof auth === 'string' && auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const body = req.body as { access_token?: unknown } | undefined;
  const fromBody = req.method === 'POST' && typeof body?.access_token === 'string' ? body.access_token : null;
  if (fromHeader !== null && fromBody !== null) return 'ambiguous';
  return fromHeader ?? fromBody;
}

export function registerUserinfo(app: FastifyInstance, deps: HttpDeps): void {
  const handler = async (req: FastifyRequest, reply: FastifyReply) => {
    // Профиль пользователя не должен оседать в кешах прокси и браузера.
    reply.header('cache-control', 'no-store');
    const token = bearerToken(req);
    if (token === 'ambiguous') return reply.status(400).send({ error: 'invalid_request' });
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
  };
  // OIDC Core 5.3.1: UserInfo обязан поддерживать GET и POST.
  app.get('/userinfo', handler);
  app.post('/userinfo', handler);
}
