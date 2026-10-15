import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { HttpDeps } from '../deps.js';
import { errorPage } from '../views/error-page.js';
import { logoutConfirmPage, loggedOutPage } from '../views/logout-page.js';
import { html } from './authorize.js';
import { readSsoCookie, clearSsoCookie } from '../cookies.js';
import { ensureCsrf, isSameOriginRequest, verifyCsrf } from '../csrf.js';

const querySchema = z.object({
  client_id: z.string().min(1),
  post_logout_redirect_uri: z.string().optional(),
});

const bodySchema = z.object({
  client_id: z.string().min(1),
  post_logout_redirect_uri: z.string().optional(),
  csrf: z.string(),
});

// post_logout_redirect_uri действителен только при точном совпадении с allowlist
// клиента; иначе трактуем как отсутствующий (open-redirect защита).
function allowedPostLogout(
  uri: string | undefined,
  whitelist: string[] | undefined,
): string | undefined {
  if (uri === undefined) return undefined;
  return whitelist?.includes(uri) ? uri : undefined;
}

export function registerLogout(app: FastifyInstance, deps: HttpDeps): void {
  app.get('/logout', async (req, reply) => {
    const parsed = querySchema.safeParse(req.query);
    if (!parsed.success)
      return html(reply, 400, errorPage('Некорректный запрос', 'Отсутствует client_id'));
    const client = await deps.clients.findClient(parsed.data.client_id);
    if (!client)
      return html(reply, 400, errorPage('Некорректный запрос', 'Неизвестное приложение'));
    const postLogoutRedirectUri = allowedPostLogout(
      parsed.data.post_logout_redirect_uri,
      client.postLogoutRedirectUris,
    );
    // Действующий токен браузера: открытие выхода не ломает формы в других вкладках.
    const csrfToken = ensureCsrf(req, reply, deps.config);
    return html(
      reply,
      200,
      logoutConfirmPage({ clientId: client.id, postLogoutRedirectUri, csrfToken }),
    );
  });

  app.post('/logout', async (req, reply) => {
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success)
      return html(reply, 400, errorPage('Некорректный запрос', 'Проверьте поля формы'));
    if (!isSameOriginRequest(req, deps.config) || !verifyCsrf(req, deps.config, parsed.data.csrf))
      return html(reply, 400, errorPage('Некорректный запрос', 'Сессия формы истекла'));
    const client = await deps.clients.findClient(parsed.data.client_id);
    if (!client)
      return html(reply, 400, errorPage('Некорректный запрос', 'Неизвестное приложение'));

    const token = readSsoCookie(req, deps.config);
    const session = token ? await deps.sso.resolve(token) : null;
    if (session) {
      await deps.sso.revoke(session.id);
      await deps.sessions.revokeAllForUserClient(session.userId, client.id);
    }
    clearSsoCookie(reply, deps.config);

    const target = allowedPostLogout(
      parsed.data.post_logout_redirect_uri,
      client.postLogoutRedirectUris,
    );
    if (target !== undefined) return reply.redirect(target, 302);
    return html(reply, 200, loggedOutPage());
  });
}
