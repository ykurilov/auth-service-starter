import Fastify, { type FastifyInstance } from 'fastify';
import { trustedProxy } from './trusted-proxy.js';
import formbody from '@fastify/formbody';
import cookie from '@fastify/cookie';
import type { HttpDeps } from './deps.js';
import { registerWellKnown } from './routes/well-known.js';
import { registerAuthorize } from './routes/authorize.js';
import { registerToken } from './routes/token.js';
import { registerUserinfo } from './routes/userinfo.js';
import { registerLogout } from './routes/logout.js';
import { registerRevoke } from './routes/revoke.js';
import { registerAdminClients } from './routes/admin-clients.js';
import { registerAssets } from './routes/assets.js';
import { homePage } from './views/home-page.js';

export function buildServer(deps: HttpDeps): FastifyInstance {
  // Forwarded-заголовки принимаем только от адресов доверенных прокси.
  const app = Fastify({
    logger: false,
    trustProxy: trustedProxy(deps.config.trustProxy),
  });
  app.register(formbody);
  // Cookie непрозрачны: секрет не задаём, целостность проверяется по хешу на сервере.
  app.register(cookie);

  // Заголовки безопасности на всех ответах. frame-ancestors 'none' + DENY:
  // страницу входа нельзя встроить в чужой iframe (clickjacking по форме).
  // nosniff запрещает браузеру угадывать MIME-тип. Директива frame-ancestors
  // не трогает загрузку ресурсов, поэтому Google-виджет на странице не страдает.
  app.addHook('onSend', async (_req, reply) => {
    reply.header('X-Frame-Options', 'DENY');
    reply.header('Content-Security-Policy', "frame-ancestors 'none'");
    reply.header('X-Content-Type-Options', 'nosniff');
  });

  // Защита в глубину: непойманная ошибка не должна утекать наружу доменным
  // сообщением или стеком. Отдаём нейтральный ответ без деталей.
  app.setErrorHandler((err, _req, reply) => {
    deps.logger.error({ err }, 'необработанная ошибка HTTP-слоя');
    return reply.status(500).send({ error: 'server_error' });
  });

  app.get('/', async (_req, reply) => reply.type('text/html; charset=utf-8').send(homePage()));
  app.get('/live', async () => ({ status: 'ok' }));
  registerAssets(app);
  registerWellKnown(app, deps);
  registerAuthorize(app, deps);
  registerToken(app, deps);
  registerUserinfo(app, deps);
  registerLogout(app, deps);
  registerRevoke(app, deps);
  registerAdminClients(app, deps);
  // Точки подключения роутов Волн B–E добавятся здесь.
  return app;
}
