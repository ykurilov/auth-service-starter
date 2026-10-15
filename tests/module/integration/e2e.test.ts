import { confirmLogout } from '../helpers.js';
import { describe, it, expect } from 'vitest';
import { makeAppFetch } from './inject-fetch.js';
import { createAuthHandlers } from '../../../module/server/handlers.js';
import { createAuthMiddleware } from '../../../module/server/nextjs.js';
import { getUser } from '../../../module/server/server.js';
import { parseCookies, SESSION_COOKIE, FLOW_COOKIE } from '../../../module/server/cookies.js';
import { unseal } from '../../../module/server/core/cookie-seal.js';
import { extractChallenge } from '../../adapters/http/helpers.js';

const APP = 'https://app.test';
const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1';
const env = { AUTH_URL: 'https://auth.example', AUTH_APP_URL: APP, AUTH_COOKIE_SECRET: SECRET };

function setCookies(res: Response): string[] {
  return (res.headers as unknown as { getSetCookie(): string[] }).getSetCookie();
}
function pick(cookies: string[], name: string): string {
  const c = cookies.find((x) => x.startsWith(`${name}=`) || (name === FLOW_COOKIE && x.startsWith(`${name}.`)));
  if (!c) throw new Error(`нет cookie ${name}`);
  return c.split(';')[0]!; // name=value
}
// «Пропустить дальше» для middleware (в Next.js — () => NextResponse.next()).
const pass = () => new Response(null, { status: 200 });

describe('E2E: модуль против живого сервиса', () => {
  it('login -> форма сервиса -> callback -> getUser -> refresh в middleware -> logout', async () => {
    const { fetch: appFetch, app } = await makeAppFetch(APP);
    // env.AUTH_URL указывает на issuer сервиса; сам транспорт — мост, поэтому
    // конкретный хост не важен, важно совпадение путей.
    const handlers = createAuthHandlers({ env, fetch: appFetch });

    // 1. login: получаем redirect на /authorize и auth_flow cookie.
    const loginRes = await handlers.GET(new Request(`${APP}/api/auth/login?next=/dashboard`));
    const authorizeUrl = new URL(loginRes.headers.get('location')!);
    const flowCookie = pick(setCookies(loginRes), FLOW_COOKIE);

    // 2. Форма входа сервиса: вход по коду. identify (отправка кода) →
    //    code/verify (обмен на code) с теми же PKCE-параметрами. Берём
    //    challenge/state прямо из authorizeUrl — они согласованы с verifier
    //    в запечатанной auth_flow.
    const baseForm: Record<string, string> = {
      client_id: authorizeUrl.searchParams.get('client_id')!,
      redirect_uri: authorizeUrl.searchParams.get('redirect_uri')!,
      code_challenge: authorizeUrl.searchParams.get('code_challenge')!,
      code_challenge_method: 'S256',
      scope: authorizeUrl.searchParams.get('scope') ?? 'openid profile email',
      state: authorizeUrl.searchParams.get('state')!,
      csrf: 'csrf-tok',
    };
    const formHeaders = { 'content-type': 'application/x-www-form-urlencoded', cookie: 'csrf=csrf-tok' };
    const identifyRes = await app.inject({
      method: 'POST',
      url: '/authorize/identify',
      payload: new URLSearchParams({ ...baseForm, email: 'user@x.com' }).toString(),
      headers: formHeaders,
    });
    const verifyRes = await app.inject({
      method: 'POST',
      url: '/authorize/code/verify',
      payload: new URLSearchParams({ ...baseForm, challenge: extractChallenge(identifyRes.body), code: 'CODE55' }).toString(),
      headers: formHeaders,
    });
    const cbLocation = new URL(verifyRes.headers['location'] as string);
    const code = cbLocation.searchParams.get('code')!;
    const state = cbLocation.searchParams.get('state')!;

    // 3. callback модуля: обмен кода, установка auth_session.
    const cbRes = await handlers.GET(
      new Request(`${APP}/api/auth/callback?code=${code}&state=${state}`, {
        headers: { cookie: flowCookie },
      }),
    );
    expect(cbRes.status).toBe(302);
    expect(new URL(cbRes.headers.get('location')!).pathname).toBe('/dashboard');
    const sessionCookie = pick(setCookies(cbRes), SESSION_COOKIE);

    // 4. getUser читает cookie.
    const user = await getUser(sessionCookie, { env });
    expect(user?.email).toBe('user@x.com');

    // 5. Истечение access -> refresh в middleware. Форсируем истечение, подменив
    //    accessTokenExpiresAt в запечатанной сессии на «сейчас».
    const sealed = parseCookies(sessionCookie)[SESSION_COOKIE]!;
    const data = await unseal<any>(sealed, SECRET);
    const { seal } = await import('../../../module/server/core/cookie-seal.js');
    const staleData = { ...data, accessTokenExpiresAt: Date.now() + 1000 }; // <120с
    const staleCookie = `${SESSION_COOKIE}=${await seal(staleData, SECRET)}`;

    const mw = createAuthMiddleware({ env, fetch: appFetch, protect: ['/dashboard'] });
    const mwRes = await mw(
      new Request(`${APP}/dashboard`, { headers: { cookie: staleCookie } }),
      pass,
    );
    expect(mwRes.status).toBe(200);
    const refreshedCookie = pick(setCookies(mwRes), SESSION_COOKIE);
    const refreshed = await unseal<any>(parseCookies(refreshedCookie)[SESSION_COOKIE]!, SECRET);
    expect(refreshed.refreshToken).not.toBe(data.refreshToken); // ротация произошла

    // 6. logout: отзыв refresh + редирект на /logout сервиса.
    const logoutRes = await confirmLogout((req) => req.method === 'POST' ? handlers.POST(req) : handlers.GET(req), APP, refreshedCookie);
    expect(logoutRes.status).toBe(302);
    expect(new URL(logoutRes.headers.get('location')!).pathname).toBe('/logout');
    expect(setCookies(logoutRes).find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toContain('Max-Age=0');

    // После отзыва refreshed-токен больше не обновляется. Форсируем истечение
    // access ещё раз (иначе middleware пропустит по свежему accessTokenExpiresAt,
    // даже не дойдя до refresh) — так же, как на шаге 5.
    const staleAfterLogout = `${SESSION_COOKIE}=${await seal({ ...refreshed, accessTokenExpiresAt: Date.now() + 1000 }, SECRET)}`;
    const afterLogout = await mw(
      new Request(`${APP}/dashboard`, { headers: { cookie: staleAfterLogout } }),
      pass,
    );
    // refresh упадёт (сессия отозвана) -> на protect редирект на login.
    expect(afterLogout.status).toBe(302);
    expect(new URL(afterLogout.headers.get('location')!).pathname).toBe('/api/auth/login');

    await app.close();
  });
});
