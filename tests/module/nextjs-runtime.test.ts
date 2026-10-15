import { describe, expect, it } from 'vitest';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { createAuthMiddleware } from '../../module/server/nextjs.js';
import { getUser, silentCheckDone } from '../../module/server/server.js';
import { seal } from '../../module/server/core/cookie-seal.js';
import { cookieNamesFor } from './helpers.js';

// Next — peer runtime приложения, не зависимость модуля. В worktree путь
// к установленному demo можно передать через AUTH_TEST_NEXT_DEMO.
let runtime: ReturnType<typeof createRequire> | undefined;
for (const root of [process.env.AUTH_TEST_NEXT_DEMO, 'examples/nextjs-demo'].filter((p): p is string => !!p)) {
  const candidate = createRequire(resolve(root, 'package.json'));
  try { candidate.resolve('next/dist/server/async-storage/request-store.js'); runtime = candidate; break; }
  catch { /* Демо может быть не установлено в чистом клоне. */ }
}
const SECRET = 'test-only-next-runtime-secret-longer-than-32';
const env = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: 'https://app.test', AUTH_COOKIE_SECRET: SECRET };
const { session: SESSION_COOKIE } = cookieNamesFor(env);
const jwt = (claims: object) => `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.signature`;

describe.skipIf(!runtime)('настоящие NextRequest/NextResponse, request store и SSR headers()/cookies()', () => {
  for (const legacyCallback of [false, true]) {
    it.each(['refresh', 'revoked', 'temporary-expired'])(`%s, callback без аргументов=${legacyCallback}`, async (outcome) => {
      const requireNext = runtime!;
      requireNext('next/dist/server/node-environment-baseline.js');
      const { NextRequest } = requireNext('next/dist/server/web/spec-extension/request.js');
      const { NextResponse } = requireNext('next/dist/server/web/spec-extension/response.js');
      const { createRequestStoreForRender } = requireNext('next/dist/server/async-storage/request-store.js');
      const { workAsyncStorage } = requireNext('next/dist/server/app-render/work-async-storage.external.js');
      const { workUnitAsyncStorage } = requireNext('next/dist/server/app-render/work-unit-async-storage.external.js');
      const { headers } = requireNext('next/dist/server/request/headers.js');
      const { cookies } = requireNext('next/dist/server/request/cookies.js');
      const React = requireNext('react');
      const { renderToStaticMarkup } = requireNext('react-dom/server');
      const sealed = await seal({ user: { id: 'u1', name: 'Прежний', roles: [] },
        accessToken: jwt({ sub: 'u1' }), refreshToken: 'r1', accessTokenExpiresAt: Date.now() - 1000 }, SECRET);
      const request = new NextRequest('https://app.test/public', { headers: {
        cookie: `${SESSION_COOKIE}=${sealed}; theme=dark`, 'x-request-id': 'keep-me', accept: 'text/html',
      } });
      const fetch: typeof globalThis.fetch = async () => outcome === 'refresh'
        ? Response.json({ access_token: jwt({ sub: 'u1', roles: ['reader'] }), id_token: jwt({ sub: 'u1', name: 'Новый' }),
          refresh_token: 'r2', token_type: 'Bearer', expires_in: 900 })
        : Response.json({ error: outcome === 'revoked' ? 'invalid_grant' : 'server_error' }, { status: outcome === 'revoked' ? 400 : 500 });
      const middleware = createAuthMiddleware({ env, fetch });
      const res = await middleware(request, legacyCallback ? () => NextResponse.next()
        : (requestHeaders) => NextResponse.next({ request: { headers: requestHeaders } }));

      // Применяем wire protocol ровно по прочитанному resolve-routes.js Next:
      // удаление всех отсутствующих в override списке и перенос остальных.
      // Далее используются реальные request store, headers/cookies API и React SSR.
      const incoming: Record<string, string> = {};
      request.headers.forEach((v: string, k: string) => { incoming[k] = v; });
      const keys = res.headers.get('x-middleware-override-headers')!.split(',').map((k) => k.trim());
      for (const key of Object.keys(incoming)) if (!keys.includes(key)) delete incoming[key];
      for (const key of keys) incoming[key] = res.headers.get(`x-middleware-request-${key}`)!;
      const forwarded = new NextRequest(request.url, { headers: incoming });
      const store = createRequestStoreForRender(forwarded, undefined, { pathname: '/public', search: '' }, {}, { tags: [] });
      const html = await workAsyncStorage.run({ route: '/public', isStaticGeneration: false }, () =>
        workUnitAsyncStorage.run(store, async () => {
          const current = await headers();
          expect(current.get('x-request-id')).toBe('keep-me');
          const currentCookies = await cookies();
          expect(currentCookies.get('theme')?.value).toBe('dark');
          // Временный сбой: cookie остаётся, страница видит «тихая проверка сделана».
          expect(!!currentCookies.get(SESSION_COOKIE)).toBe(outcome !== 'revoked');
          expect(silentCheckDone(current.get('cookie'), {}, { env })).toBe(outcome === 'temporary-expired');
          const user = await getUser(current.get('cookie'), { env });
          return renderToStaticMarkup(React.createElement('div', null, user?.name ?? 'anonymous'));
        }));
      expect(html).toBe(outcome === 'refresh' ? '<div>Новый</div>' : '<div>anonymous</div>');
      const set = res.headers.getSetCookie();
      if (outcome === 'temporary-expired') expect(set).toEqual([]);
      else expect(set.join().includes('Max-Age=0')).toBe(outcome === 'revoked');
    });
  }
});
