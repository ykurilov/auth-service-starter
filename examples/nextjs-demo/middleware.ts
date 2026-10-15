import { createAuthMiddleware } from '@/auth';
import { NextResponse, type NextRequest } from 'next/server';

const auth = createAuthMiddleware({ env: process.env, protect: ['/dashboard'] });

export function middleware(req: NextRequest) {
  // Второй аргумент обязателен: «пропустить запрос» в Next.js — это
  // NextResponse.next(), модуль сам его собрать не может.
  return auth(req, (headers) => NextResponse.next({ request: { headers } }));
}

// /api/auth/* исключён: маршрутам входа и выхода защита не нужна.
export const config = { matcher: ['/((?!api/auth/|_next/static|_next/image|favicon.ico).*)'] };
