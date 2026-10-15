import { describe, it, expect } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { makeAppFetch } from './inject-fetch.js';
import { createAuthHandlers } from '../../../module/server/handlers.js';
import { getUser } from '../../../module/server/server.js';
import { SESSION_COOKIE, FLOW_COOKIE, SILENT_CHECK_COOKIE } from '../../../module/server/cookies.js';
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
  return c.split(';')[0]!;
}
function injectSetCookie(res: { headers: Record<string, unknown> }, name: string): string {
  const raw = res.headers['set-cookie'];
  const lines = Array.isArray(raw) ? raw.map(String) : [String(raw ?? '')];
  const line = lines.find((l) => l.startsWith(`${name}=`));
  if (!line) throw new Error(`нет cookie ${name} от сервиса`);
  return line.split(';')[0]!;
}
// Браузер идёт по Location сервиса: тот же /authorize, но внутри процесса.
async function followAuthorize(app: FastifyInstance, authorizeUrl: URL, cookie?: string) {
  const res = await app.inject({
    method: 'GET',
    url: authorizeUrl.pathname + authorizeUrl.search,
    headers: cookie ? { cookie } : {},
  });
  return res;
}

// Обычный вход по почте: оставляет в «браузере» SSO-cookie сервиса.
async function loginInteractively(app: FastifyInstance, authorizeUrl: URL): Promise<string> {
  const form: Record<string, string> = {
    client_id: authorizeUrl.searchParams.get('client_id')!,
    redirect_uri: authorizeUrl.searchParams.get('redirect_uri')!,
    code_challenge: authorizeUrl.searchParams.get('code_challenge')!,
    code_challenge_method: 'S256',
    scope: authorizeUrl.searchParams.get('scope')!,
    state: authorizeUrl.searchParams.get('state')!,
    csrf: 'csrf-tok',
  };
  const headers = { 'content-type': 'application/x-www-form-urlencoded', cookie: 'csrf=csrf-tok' };
  const identifyRes = await app.inject({
    method: 'POST',
    url: '/authorize/identify',
    payload: new URLSearchParams({ ...form, email: 'user@x.com' }).toString(),
    headers,
  });
  const verify = await app.inject({
    method: 'POST',
    url: '/authorize/code/verify',
    payload: new URLSearchParams({ ...form, challenge: extractChallenge(identifyRes.body), code: 'CODE55' }).toString(),
    headers,
  });
  expect(verify.statusCode).toBe(302);
  return injectSetCookie(verify, 'sso');
}

describe('E2E: тихий вход модуля против живого сервиса', () => {
  it('нет SSO-сессии -> login_required -> метка и сразу обычный вход, без цикла', async () => {
    const { fetch: appFetch, app } = await makeAppFetch(APP);
    const handlers = createAuthHandlers({ env, fetch: appFetch });

    const loginRes = await handlers.GET(new Request(`${APP}/api/auth/login?next=/dashboard`));
    const silentUrl = new URL(loginRes.headers.get('location')!);
    expect(silentUrl.searchParams.get('prompt')).toBe('none');

    const authRes = await followAuthorize(app, silentUrl);
    expect(authRes.statusCode).toBe(302);
    const cb = new URL(authRes.headers['location'] as string);
    expect(cb.searchParams.get('error')).toBe('login_required');

    const cbRes = await handlers.GET(
      new Request(cb.toString(), { headers: { cookie: pick(setCookies(loginRes), FLOW_COOKIE) } }),
    );
    const interactiveUrl = new URL(cbRes.headers.get('location')!);
    expect(interactiveUrl.pathname).toBe('/authorize');
    expect(interactiveUrl.searchParams.has('prompt')).toBe(false);
    expect(pick(setCookies(loginRes), SILENT_CHECK_COOKIE)).toBe(`${SILENT_CHECK_COOKIE}=1`);

    // Обычный /authorize без SSO показывает форму входа, а не редирект.
    const page = await followAuthorize(app, interactiveUrl);
    expect(page.statusCode).toBe(200);
    await app.close();
  });

  it('живая SSO-сессия -> code без экрана входа -> сессия приложения -> сразу на next', async () => {
    const { fetch: appFetch, app } = await makeAppFetch(APP);
    const handlers = createAuthHandlers({ env, fetch: appFetch });

    // Пользователь уже вошёл в единый SSO (например, в другом приложении).
    const first = await handlers.GET(new Request(`${APP}/api/auth/login?silent=0`));
    const sso = await loginInteractively(app, new URL(first.headers.get('location')!));

    // Cookie приложения нет — модуль идёт тихо.
    const loginRes = await handlers.GET(new Request(`${APP}/api/auth/login?next=/dashboard`));
    const silentUrl = new URL(loginRes.headers.get('location')!);
    const authRes = await followAuthorize(app, silentUrl, sso);
    expect(authRes.statusCode).toBe(302);
    const cb = new URL(authRes.headers['location'] as string);
    expect(cb.searchParams.get('code')).toBeTruthy();

    const cbRes = await handlers.GET(
      new Request(cb.toString(), { headers: { cookie: pick(setCookies(loginRes), FLOW_COOKIE) } }),
    );
    expect(cbRes.headers.get('location')).toBe(`${APP}/dashboard`);
    const user = await getUser(pick(setCookies(cbRes), SESSION_COOKIE), { env });
    expect(user?.email).toBe('user@x.com');
    await app.close();
  });

  it('external-приложение: живая SSO -> consent_required -> обычный вход с экраном согласия, без профиля тихо', async () => {
    const { fetch: appFetch, app } = await makeAppFetch(APP, 'external');
    const handlers = createAuthHandlers({ env, fetch: appFetch });
    const first = await handlers.GET(new Request(`${APP}/api/auth/login?silent=0`));
    const sso = await loginInteractively(app, new URL(first.headers.get('location')!));

    const loginRes = await handlers.GET(new Request(`${APP}/api/auth/login?next=/dashboard`));
    const silentUrl = new URL(loginRes.headers.get('location')!);
    const authRes = await followAuthorize(app, silentUrl, sso);
    const cb = new URL(authRes.headers['location'] as string);
    expect(cb.searchParams.get('error')).toBe('consent_required');
    expect(cb.searchParams.get('code')).toBeNull();

    // Модуль переходит к обычному входу, сервис показывает «Продолжить как …».
    const cbRes = await handlers.GET(
      new Request(cb.toString(), { headers: { cookie: pick(setCookies(loginRes), FLOW_COOKIE) } }),
    );
    const interactiveUrl = new URL(cbRes.headers.get('location')!);
    expect(interactiveUrl.searchParams.has('prompt')).toBe(false);
    const page = await followAuthorize(app, interactiveUrl, sso);
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain('/authorize/confirm');
    await app.close();
  });
});
