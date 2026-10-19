import { describe, it, expect } from 'vitest';
import { createAuthHandlers } from '../../module/server/handlers.js';
import { seal } from '../../module/server/core/cookie-seal.js';
import { cookieNamesFor, nextOfState } from './helpers.js';

const APP = 'https://app.test';
const SECRET = 'test-only-cookie-secret-at-least-32-characters';
const env = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: APP, AUTH_COOKIE_SECRET: SECRET };
const names = cookieNamesFor(env);
const req = (path: string, cookie = '') => new Request(APP + path, { headers: { cookie } });
const pair = (line: string) => line.split(';')[0]!;
const flowLines = (res: Response) => res.headers.getSetCookie().filter((c) => c.startsWith(`${names.flow}.`) && !c.includes('Max-Age=0'));

async function openFlows(count: number) {
  const h = createAuthHandlers({ env });
  const cookies: string[] = [];
  for (let i = 0; i < count; i++) {
    const res = await h.GET(req('/api/auth/login?silent=0&next=/', cookies.join('; ')));
    cookies.push(pair(flowLines(res)[0]!));
  }
  return cookies;
}

// Протухшая попытка: имя своё, но печать не читается (истёк срок или другой секрет).
const staleFlow = `${names.flow}.${'s'.repeat(22)}=${'v2.x.y'}`;

describe('R17: сбой своего обычного входа', () => {
  it('при живой старой сессии показывает страницу ошибки, а не молча ведёт на старую сессию', async () => {
    const h = createAuthHandlers({ env, fetch: (async () => Response.json({ error: 'server_error' }, { status: 500 })) as typeof fetch });
    const live = `${names.session}=${await seal({ user: { id: 'A', roles: [] }, accessToken: 'a', refreshToken: 'r',
      accessTokenExpiresAt: Date.now() + 600_000 }, SECRET)}`;
    const login = await h.GET(req('/api/auth/login?silent=0&next=/dashboard', live));
    const state = new URL(login.headers.get('location')!).searchParams.get('state')!;
    const res = await h.GET(req(`/api/auth/callback?code=c&state=${state}`, `${live}; ${pair(flowLines(login)[0]!)}`));
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
    expect(await res.text()).toContain('Не удалось войти');
    expect(res.headers.getSetCookie().some((c) => c.startsWith(`${names.session}=`))).toBe(false);
  });
});

// Сверх лимита новая попытка вытесняет самую старую: попытка живёт час, и
// брошенные вкладки не должны блокировать вход (T13).
describe('R18: лимит незавершённых входов', () => {
  const clearOf = (cookie: string) => `${cookie.split('=')[0]}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`;

  it.each(['silent=1&next=/blog', 'silent=0&next=/'])('%s сверх лимита стартует, вытесняя самую старую и протухшие', async (query) => {
    const flows = await openFlows(4);
    const res = await createAuthHandlers({ env }).GET(req(`/api/auth/login?${query}`, [...flows, staleFlow].join('; ')));
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get('location')!).origin).toBe('https://auth.test');
    expect(flowLines(res)).toHaveLength(1);
    expect(res.headers.getSetCookie().filter((c) => c.includes('Max-Age=0')).sort())
      .toEqual([clearOf(staleFlow), clearOf(flows[0]!)].sort());
  });

  it('silent=1 с меткой тоже очищает протухшие попытки', async () => {
    const res = await createAuthHandlers({ env }).GET(req('/api/auth/login?silent=1&next=/', `${names.silentCheck}=1; ${staleFlow}`));
    expect(res.status).toBe(302);
    expect(res.headers.getSetCookie().some((c) => c.includes('Max-Age=0'))).toBe(true);
  });
});

describe('R18: длинный next', () => {
  async function flowOf(query: string) {
    const res = await createAuthHandlers({ env }).GET(req(`/api/auth/login?${query}`));
    const line = pair(flowLines(res)[0]!);
    const next = await nextOfState(new URL(res.headers.get('location')!).searchParams.get('state'), SECRET);
    return { line, flow: { next } };
  }

  it('next из 1023 кавычек не раздувает flow-cookie выше лимита браузера', async () => {
    const next = '/' + '"'.repeat(1023);
    const { line } = await flowOf(`silent=1&next=${encodeURIComponent(next)}`);
    expect(new TextEncoder().encode(line).length).toBeLessThanOrEqual(4096);
  });

  it('обычный next длиннее 1024 байт сохраняется', async () => {
    const next = '/search?q=' + 'x'.repeat(1500);
    for (const silent of ['0', '1']) {
      const { line, flow } = await flowOf(`silent=${silent}&next=${encodeURIComponent(next)}`);
      expect(flow!.next).toBe(next);
      expect(new TextEncoder().encode(line).length).toBeLessThanOrEqual(4096);
    }
  });

  it('слишком длинный next теряет query, но не страницу', async () => {
    const { flow } = await flowOf(`silent=0&next=${encodeURIComponent('/reports/42?q=' + 'x'.repeat(5000))}`);
    expect(flow!.next).toBe('/reports/42');
  });

  it('next, который не влезает в cookie даже без query, заменяется на /', async () => {
    const { line, flow } = await flowOf(`silent=1&next=${encodeURIComponent('/' + '"'.repeat(2000))}`);
    expect(flow!.next).toBe('/');
    expect(new TextEncoder().encode(line).length).toBeLessThanOrEqual(4096);
  });
});
