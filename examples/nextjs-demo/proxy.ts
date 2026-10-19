import { createAuthMiddleware } from '@/auth';
import { NextResponse, type NextRequest } from 'next/server';

// Как и обработчики входа, создаётся при первом запросе: сборка идёт без AUTH_*.
let auth: ReturnType<typeof createAuthMiddleware> | undefined;

export function proxy(req: NextRequest) {
  auth ??= createAuthMiddleware({ env: process.env, protect: ['/dashboard'] });
  // Второй аргумент обязателен: «пропустить запрос» в Next.js — это
  // NextResponse.next(), модуль сам его собрать не может.
  return auth(req, (headers) => NextResponse.next({ request: { headers } }));
}

// /api/auth/* исключён: маршрутам входа и выхода защита не нужна.
// Proxy в Next.js 16 всегда работает в Node.js, в одном процессе с route
// handlers: выход и новый вход гасят refresh, начатый здесь.
export const config = { matcher: ['/((?!api/auth/|_next/static|_next/image|favicon.ico).*)'] };
