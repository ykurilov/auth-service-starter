import { describe, it, expect } from 'vitest';
import { makeAppFetch } from './inject-fetch.js';
import { createAuthHandlers } from '../../../module/server/handlers.js';
import { createAuthMiddleware } from '../../../module/server/nextjs.js';
import { seal, unseal } from '../../../module/server/core/cookie-seal.js';
import { parseCookies } from '../../../module/server/cookies.js';
import { cookieNamesFor } from '../helpers.js';
import { extractChallenge } from '../../adapters/http/helpers.js';

const APP = 'https://app.test';
const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1';
const env = { AUTH_URL: 'https://auth.example', AUTH_APP_URL: APP, AUTH_COOKIE_SECRET: SECRET };
const { session: SESSION_COOKIE, flow: FLOW_COOKIE } = cookieNamesFor(env);

function setCookies(res: Response): string[] {
  return (res.headers as unknown as { getSetCookie(): string[] }).getSetCookie();
}
function pick(cookies: string[], name: string): string {
  const c = cookies.find((x) => x.startsWith(`${name}=`) || (name === FLOW_COOKIE && x.startsWith(`${name}.`)))!;
  return c.split(';')[0]!;
}
// «Пропустить дальше» для middleware (в Next.js — () => NextResponse.next()).
const pass = () => new Response(null, { status: 200 });

// Логинимся по коду и возвращаем свежую session cookie.
async function login(app: any, appFetch: typeof fetch): Promise<string> {
  const handlers = createAuthHandlers({ env, fetch: appFetch });
  const loginRes = await handlers.GET(new Request(`${APP}/api/auth/login`));
  const authorizeUrl = new URL(loginRes.headers.get('location')!);
  const flowCookie = pick(setCookies(loginRes), FLOW_COOKIE);
  const base: Record<string, string> = {
    client_id: authorizeUrl.searchParams.get('client_id')!,
    redirect_uri: authorizeUrl.searchParams.get('redirect_uri')!,
    code_challenge: authorizeUrl.searchParams.get('code_challenge')!,
    code_challenge_method: 'S256',
    scope: 'openid',
    state: authorizeUrl.searchParams.get('state')!,
    csrf: 'csrf-tok',
  };
  const formHeaders = { 'content-type': 'application/x-www-form-urlencoded', cookie: 'csrf=csrf-tok' };
  const identifyRes = await app.inject({
    method: 'POST',
    url: '/authorize/identify',
    payload: new URLSearchParams({ ...base, email: 'user@x.com' }).toString(),
    headers: formHeaders,
  });
  const verifyRes = await app.inject({
    method: 'POST',
    url: '/authorize/code/verify',
    payload: new URLSearchParams({ ...base, challenge: extractChallenge(identifyRes.body), code: 'CODE55' }).toString(),
    headers: formHeaders,
  });
  const cb = new URL(verifyRes.headers['location'] as string);
  const cbRes = await handlers.GET(
    new Request(`${APP}/api/auth/callback?code=${cb.searchParams.get('code')}&state=${cb.searchParams.get('state')}`, {
      headers: { cookie: flowCookie },
    }),
  );
  return pick(setCookies(cbRes), SESSION_COOKIE);
}

describe('гонка: три параллельных refresh через модуль', () => {
  it('все три успешны, сессия жива', async () => {
    const { fetch: appFetch, app } = await makeAppFetch(APP);
    const sessionCookie = await login(app, appFetch);

    // Форсируем истечение, чтобы middleware пошёл в refresh.
    const data = await unseal<any>(parseCookies(sessionCookie)[SESSION_COOKIE]!, SECRET);
    const stale = `${SESSION_COOKIE}=${await seal({ ...data, accessTokenExpiresAt: Date.now() + 1000 }, SECRET)}`;

    // Три ОТДЕЛЬНЫХ инстанса middleware — чтобы обойти in-process дедуп и реально
    // ударить сервис тремя параллельными refresh одним токеном.
    const mws = [0, 1, 2].map(() => createAuthMiddleware({ env, fetch: appFetch }));
    const results = await Promise.all(
      mws.map((mw) => mw(new Request(`${APP}/x`, { headers: { cookie: stale } }), pass)),
    );
    // Каждый из трёх обязан УСПЕШНО обновиться: свежая auth_session на 30 дней
    // (Max-Age=2592000, не чистка Max-Age=0) с валидным содержимым. Один только
    // статус 200 ловил бы и провал refresh на не-protect пути.
    for (const res of results) {
      expect(res.status).toBe(200);
      const set = setCookies(res).find((c) => c.startsWith(`${SESSION_COOKIE}=`))!;
      expect(set).toContain('Max-Age=2592000');
      const inner = await unseal<any>(parseCookies(set.split(';')[0]!)[SESSION_COOKIE]!, SECRET);
      expect(inner).not.toBeNull();
      expect(inner.user.id).toBe(data.user.id);
    }

    // Сессия по-прежнему обновляема: берём голову из первого результата и рефрешим ещё раз.
    const newCookie = pick(setCookies(results[0]!), SESSION_COOKIE);
    const newData = await unseal<any>(parseCookies(newCookie)[SESSION_COOKIE]!, SECRET);
    const staleNew = `${SESSION_COOKIE}=${await seal({ ...newData, accessTokenExpiresAt: Date.now() + 1000 }, SECRET)}`;
    const mw2 = createAuthMiddleware({ env, fetch: appFetch });
    const again = await mw2(new Request(`${APP}/x`, { headers: { cookie: staleNew } }), pass);
    expect(again.status).toBe(200);
    expect(setCookies(again).find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toContain('Max-Age=2592000');

    await app.close();
  });
});
