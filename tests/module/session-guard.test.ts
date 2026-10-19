import { describe, it, expect } from 'vitest';
import { createSessionGuard } from '../../module/server/session-guard.js';
import { seal, unseal } from '../../module/server/core/cookie-seal.js';
import { parseCookies } from '../../module/server/cookies.js';
import { cookieNamesFor } from './helpers.js';

// Общая защита без фреймворка: по запросу решает «пропустить» (с пользователем
// и cookie, которые надо дописать к ответу) или «отказать» (готовый ответ).
// Подробные правила отказа (401 против редиректа, Vary) проверяет nextjs.test.ts
// через адаптер Next.js — здесь форма решения.

const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1';
const env = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: 'https://app.test', AUTH_COOKIE_SECRET: SECRET };
const { session: SESSION_COOKIE } = cookieNamesFor(env);

function fakeJwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(unescape(encodeURIComponent(JSON.stringify(o))))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${b64({ alg: 'RS256' })}.${b64(payload)}.sig`;
}
async function sessionCookie(expiresInMs: number) {
  const data = {
    user: { id: 'u1', name: 'Старое имя', roles: [] },
    accessToken: fakeJwt({ sub: 'u1' }),
    refreshToken: 'r1',
    accessTokenExpiresAt: Date.now() + expiresInMs,
  };
  return `${SESSION_COOKIE}=${await seal(data, SECRET)}`;
}
const noNetwork = (async () => {
  throw new Error('сеть не нужна');
}) as typeof fetch;
const refreshOk = (async () =>
  Response.json({
    access_token: fakeJwt({ sub: 'u1', roles: ['editor'] }),
    id_token: fakeJwt({ sub: 'u1', name: 'Новое имя' }),
    refresh_token: 'r2',
    token_type: 'Bearer',
    expires_in: 900,
  })) as typeof fetch;
const refreshFails = (async () => Response.json({ error: 'invalid_grant' }, { status: 400 })) as typeof fetch;

describe('createSessionGuard', () => {
  it('обновлённая cookie Secure по AUTH_APP_URL, даже если запрос пришёл как http://localhost', async () => {
    const check = createSessionGuard({ env, fetch: refreshOk });
    const cookie = await sessionCookie(60 * 1000);
    const decision = await check(new Request('http://localhost:3000/app', { headers: { cookie } }));
    if (decision.kind !== 'pass') throw new Error('ожидали pass');
    expect(decision.setCookies[0]).toContain('Secure');
  });

  it('маршруты модуля /api/auth/* -> пропустить без обновления сессии и без cookie', async () => {
    const check = createSessionGuard({ env, fetch: noNetwork, protect: ['/'] });
    const cookie = await sessionCookie(60 * 1000);
    const decision = await check(new Request('https://app.test/api/auth/logout', { headers: { cookie } }));
    expect(decision).toEqual({ kind: 'pass', user: { id: 'u1', name: 'Старое имя', roles: [] }, setCookies: [] });
  });

  it('нет сессии на открытом пути -> пропустить без пользователя и без cookie', async () => {
    const check = createSessionGuard({ env, fetch: noNetwork });
    const decision = await check(new Request('https://app.test/'));
    expect(decision).toEqual({ kind: 'pass', user: null, setCookies: [] });
  });

  it('свежая сессия -> пропустить с пользователем из cookie, без сети', async () => {
    const check = createSessionGuard({ env, fetch: noNetwork, protect: ['/'] });
    const cookie = await sessionCookie(5 * 60 * 1000);
    const decision = await check(new Request('https://app.test/app', { headers: { cookie } }));
    expect(decision).toEqual({ kind: 'pass', user: { id: 'u1', name: 'Старое имя', roles: [] }, setCookies: [] });
  });

  it('токен истекает -> пропустить с пользователем из обновлённой сессии и новой cookie', async () => {
    const check = createSessionGuard({ env, fetch: refreshOk });
    const cookie = await sessionCookie(60 * 1000);
    const decision = await check(new Request('https://app.test/app', { headers: { cookie } }));
    if (decision.kind !== 'pass') throw new Error('ожидали pass');
    expect(decision.user).toEqual({ id: 'u1', name: 'Новое имя', roles: ['editor'] });
    expect(decision.setCookies).toHaveLength(1);
    const sealed = parseCookies(decision.setCookies[0]!.split(';')[0]!)[SESSION_COOKIE]!;
    expect((await unseal<{ refreshToken: string }>(sealed, SECRET))!.refreshToken).toBe('r2');
  });

  it('обновление не удалось на открытом пути -> пропустить анонимно, cookie не стирать (T14)', async () => {
    const check = createSessionGuard({ env, fetch: refreshFails });
    const cookie = await sessionCookie(60 * 1000);
    const decision = await check(new Request('https://app.test/', { headers: { cookie } }));
    if (decision.kind !== 'pass') throw new Error('ожидали pass');
    expect(decision.user).toBeNull();
    expect(decision.setCookies).toEqual([]);
  });

  it('нет сессии на защищённой странице -> отказ с редиректом на вход', async () => {
    const check = createSessionGuard({ env, fetch: noNetwork, protect: ['/app'] });
    const decision = await check(new Request('https://app.test/app/x?tab=1'));
    if (decision.kind !== 'deny') throw new Error('ожидали deny');
    expect(decision.response.status).toBe(302);
    const location = new URL(decision.response.headers.get('location')!);
    expect(location.pathname).toBe('/api/auth/login');
    expect(location.searchParams.get('next')).toBe('/app/x?tab=1');
  });

  it('нет сессии, запрос данных к защищённому API -> отказ 401', async () => {
    const check = createSessionGuard({ env, fetch: noNetwork, protect: ['/api/notes'] });
    const decision = await check(
      new Request('https://app.test/api/notes', { headers: { 'sec-fetch-mode': 'cors' } }),
    );
    if (decision.kind !== 'deny') throw new Error('ожидали deny');
    expect(decision.response.status).toBe(401);
  });

  it('маршруты входа /api/auth/* пропускаются даже при protect: ["/"]', async () => {
    const check = createSessionGuard({ env, fetch: noNetwork, protect: ['/'] });
    const decision = await check(new Request('https://app.test/api/auth/callback?code=x'));
    expect(decision.kind).toBe('pass');
  });
});
