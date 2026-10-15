import { createAuthHandlers } from './handlers.js';
import { createSessionGuard, type GuardOptions } from './session-guard.js';
import { getUser } from './server.js';
import type { SessionUser } from './core/session-data.js';

// Адаптер Hono: маршруты входа, защита запросов и пользователь в обработчике.
//
//   const auth = createHonoAuth({ env: process.env, protect: ['/api/notes'] });
//   app.use(auth.guard);                    // до остальных маршрутов
//   app.on(['GET', 'POST'], '/api/auth/*', auth.routes);    // login, callback, logout, me
//   app.get('/api/notes', async (c) => c.json({ user: await auth.user(c) }));
//
// Пакет hono не импортируем: от контекста нужны только req.raw и header().
// Так папку модуля можно копировать и в приложение без Hono — лишний файл не
// ломает проверку типов. Context любого Hono-приложения подходит под эти типы.
interface HonoContextLike {
  req: { raw: Request };
  header(name: string, value: string, options?: { append?: boolean }): void;
}
type HonoNext = () => Promise<void>;

export type HonoAuthOptions = GuardOptions;

export function createHonoAuth(options: HonoAuthOptions = {}) {
  const handlers = createAuthHandlers(options);
  const check = createSessionGuard(options);
  // Пользователь, которого защита нашла (или обновила) для этого запроса.
  // Ключ — исходный Request: он один на весь путь запроса по приложению.
  const users = new WeakMap<Request, SessionUser | null>();

  async function guard(c: HonoContextLike, next: HonoNext): Promise<Response | void> {
    const decision = await check(c.req.raw);
    if (decision.kind === 'deny') return decision.response;
    users.set(c.req.raw, decision.user);
    await next();
    // После next() ответ уже готов: header() дописывает cookie и к ответу
    // c.json(), и к голому Response обработчика.
    for (const cookie of decision.setCookies) c.header('set-cookie', cookie, { append: true });
  }

  // GET показывает страницы и читает сессию; POST — только подтверждённый
  // выход. HEAD и остальные методы не выполняют действий.
  async function routes(c: HonoContextLike): Promise<Response> {
    if (c.req.raw.method === 'POST') return handlers.POST(c.req.raw);
    return handlers.GET(c.req.raw);
  }

  // Кто вошёл. После guard — пользователь обновлённой сессии; без guard —
  // из cookie запроса.
  async function user(c: { req: { raw: Request } }): Promise<SessionUser | null> {
    const raw = c.req.raw;
    if (users.has(raw)) return users.get(raw) ?? null;
    return getUser(raw.headers.get('cookie'), options);
  }

  return { guard, routes, user };
}
