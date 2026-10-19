import { confirmLogout, cookieNamesFor, nextOfState } from './helpers.js';
import { describe, it, expect, vi } from 'vitest';
import { createAuthHandlers } from '../../module/server/handlers.js';
import { unseal } from '../../module/server/core/cookie-seal.js';
import { parseCookies, SILENT_CHECK_PARAM } from '../../module/server/cookies.js';

const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1';
const env = {
  AUTH_URL: 'https://auth.test',
  AUTH_APP_URL: 'https://app.test',
  AUTH_COOKIE_SECRET: SECRET,
};
const { session: SESSION_COOKIE, flow: FLOW_COOKIE, silentCheck: SILENT_CHECK_COOKIE } = cookieNamesFor(env);

// Собирает Set-Cookie из ответа в карту name->serialized.
function setCookies(res: Response): string[] {
  // Web Headers объединяет несколько Set-Cookie; getSetCookie() их разделяет.
  return (res.headers as unknown as { getSetCookie(): string[] }).getSetCookie();
}
function fakeJwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(unescape(encodeURIComponent(JSON.stringify(o))))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${b64({ alg: 'RS256' })}.${b64(payload)}.sig`;
}

// Сбой входа — страница ошибки, а не редирект: редирект на защищённую
// страницу снова запустил бы вход, и получился бы круг.
function expectErrorPage(res: Response) {
  expect(res.status).toBe(400);
  expect(res.headers.get('location')).toBeNull();
  expect(res.headers.get('content-type')).toContain('text/html');
}

function handlersWith(handler: (req: Request) => Promise<Response> | Response) {
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    return handler(req);
  }) as typeof fetch;
  return createAuthHandlers({ env, fetch: fetchImpl });
}

describe('GET /api/auth/login', () => {
  it('редиректит на /authorize и ставит запечатанную auth_flow с next', async () => {
    const { GET } = handlersWith(() => new Response(''));
    const res = await GET(new Request('https://app.test/api/auth/login?next=/dashboard'));
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get('location')!);
    expect(loc.origin + loc.pathname).toBe('https://auth.test/authorize');
    const state = loc.searchParams.get('state');
    const challenge = loc.searchParams.get('code_challenge');
    expect(state).toBeTruthy();
    expect(challenge).toBeTruthy();

    const flowCookie = setCookies(res).find((c) => c.startsWith(`${FLOW_COOKIE}.`))!;
    expect(flowCookie).toContain('Max-Age=3600'); // час: код из письма с продлениями
    // flowCookie найдена через find(startsWith(FLOW_COOKIE=)) — сегмент и ключ гарантированы.
    const sealed = Object.values(parseCookies(flowCookie.split(';')[0]!))[0]!;
    const flow = await unseal<{ verifier: string; state: string }>(sealed, SECRET);
    expect(flow!.state.split('~')[0]).toBe(state!.split('~')[0]);
    expect(await nextOfState(state, SECRET)).toBe('/dashboard');
    expect(flow!.verifier).toBeTruthy();
  });

  it('внешний/абсолютный next отбрасывается (только относительный путь)', async () => {
    const { GET } = handlersWith(() => new Response(''));
    const res = await GET(new Request('https://app.test/api/auth/login?next=https://evil.com'));
    const state = new URL(res.headers.get('location')!).searchParams.get('state');
    expect(await nextOfState(state, SECRET)).toBe('/');
  });
});

// Secure решает адрес приложения, а не адрес запроса: за прокси сервер
// часто видит http://localhost, хотя браузер пришёл по https.
describe('Secure у cookie — по AUTH_APP_URL', () => {
  function flowCookieOf(res: Response): string {
    return setCookies(res).find((c) => (c.startsWith(`${FLOW_COOKIE}.`) || c.startsWith('auth_flow.')))!;
  }

  it('AUTH_APP_URL https, запрос пришёл как http://localhost (за прокси) -> Secure', async () => {
    const { GET } = createAuthHandlers({ env, fetch: (async () => new Response('')) as typeof fetch });
    const res = await GET(new Request('http://localhost:3000/api/auth/login?next=/'));
    expect(flowCookieOf(res)).toContain('Secure');
  });

  it('AUTH_APP_URL http://localhost -> без Secure', async () => {
    const local = { ...env, AUTH_APP_URL: 'http://localhost:3007' };
    const { GET } = createAuthHandlers({ env: local, fetch: (async () => new Response('')) as typeof fetch });
    const res = await GET(new Request('http://localhost:3007/api/auth/login?next=/'));
    expect(flowCookieOf(res)).not.toContain('Secure');
  });

  it('AUTH_APP_URL http://127.0.0.1 -> без Secure', async () => {
    const local = { ...env, AUTH_APP_URL: 'http://127.0.0.1:3007' };
    const { GET } = createAuthHandlers({ env: local, fetch: (async () => new Response('')) as typeof fetch });
    const res = await GET(new Request('http://127.0.0.1:3007/api/auth/login?next=/'));
    expect(flowCookieOf(res)).not.toContain('Secure');
  });

  it('AUTH_APP_URL HTTP на обычном домене отклоняется до отправки токенов', () => {
    const plain = { ...env, AUTH_APP_URL: 'http://app.test' };
    expect(() => createAuthHandlers({ env: plain })).toThrow(/HTTPS/);
  });
});

describe('GET /api/auth/callback', () => {
  async function loginFlowCookie(next = '/dashboard') {
    const { GET } = handlersWith(() => new Response(''));
    const res = await GET(new Request(`https://app.test/api/auth/login?next=${next}`));
    const loc = new URL(res.headers.get('location')!);
    const state = loc.searchParams.get('state')!;
    const flowCookie = setCookies(res).find((c) => c.startsWith(`${FLOW_COOKIE}.`))!;
    // Первый сегмент — пара name=value, flowCookie гарантирована find(...)! выше.
    const cookieHeader = flowCookie.split(';')[0]!;
    return { state, cookieHeader };
  }

  it('успех: меняет код на токены, ставит auth_session, чистит auth_flow, редиректит на next', async () => {
    const { state, cookieHeader } = await loginFlowCookie('/dashboard');
    const { GET } = handlersWith(async (req) => {
      if (req.url.endsWith('/oauth/token')) {
        return Response.json({
          access_token: fakeJwt({ sub: 'u1', roles: ['admin'] }),
          id_token: fakeJwt({ sub: 'u1', email: 'a@b.co', name: 'Аня' }),
          refresh_token: 'r1',
          token_type: 'Bearer',
          expires_in: 900,
        });
      }
      return new Response('', { status: 404 });
    });
    const res = await GET(
      new Request(`https://app.test/api/auth/callback?code=c&state=${state}`, {
        headers: { cookie: cookieHeader },
      }),
    );
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get('location')!).pathname).toBe('/dashboard');

    const cookies = setCookies(res);
    const session = cookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`))!;
    expect(session).toContain('Max-Age=2592000'); // 30 дней
    const flowCleared = cookies.find((c) => c.startsWith(`${FLOW_COOKIE}.`))!;
    expect(flowCleared).toContain('Max-Age=0');

    // session найдена через find(startsWith(SESSION_COOKIE=)) — сегмент и ключ гарантированы.
    const sealed = parseCookies(session.split(';')[0]!)[SESSION_COOKIE]!;
    const data = await unseal<{ user: { id: string } }>(sealed, SECRET);
    expect(data!.user.id).toBe('u1');
  });

  it('несовпадение state -> страница ошибки без очистки чужой auth_flow, сессия не трогается', async () => {
    const { cookieHeader } = await loginFlowCookie();
    const { GET } = handlersWith(() => new Response('', { status: 500 }));
    const res = await GET(
      new Request('https://app.test/api/auth/callback?code=c&state=ЧУЖОЙ', {
        headers: { cookie: cookieHeader },
      }),
    );
    expectErrorPage(res);
    const cookies = setCookies(res);
    expect(cookies.find((c) => c.startsWith(`${FLOW_COOKIE}.`))).toBeUndefined();
    // auth_session НЕ ставится и НЕ чистится: подброшенный битый callback
    // не должен разлогинивать уже вошедшего пользователя.
    expect(cookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBeUndefined();
  });

  it('провайдер вернул ?error= -> страница ошибки', async () => {
    const { cookieHeader } = await loginFlowCookie();
    const { GET } = handlersWith(() => new Response(''));
    const res = await GET(
      new Request('https://app.test/api/auth/callback?error=access_denied', {
        headers: { cookie: cookieHeader },
      }),
    );
    expectErrorPage(res);
  });

  it('обмен кода упал (invalid_grant) -> страница ошибки с чисткой auth_flow, сессия не трогается', async () => {
    const { state, cookieHeader } = await loginFlowCookie();
    const { GET } = handlersWith(async () => Response.json({ error: 'invalid_grant' }, { status: 400 }));
    const res = await GET(
      new Request(`https://app.test/api/auth/callback?code=c&state=${state}`, {
        headers: { cookie: cookieHeader },
      }),
    );
    expectErrorPage(res);
    const cookies = setCookies(res);
    expect(cookies.find((c) => c.startsWith(`${FLOW_COOKIE}.`))).toContain('Max-Age=0');
    expect(cookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBeUndefined();
  });
});

describe('тихий вход (prompt=none)', () => {
  const MARK = `${SILENT_CHECK_COOKIE}=1`;
  const tokenOk = async (req: Request) =>
    req.url.endsWith('/oauth/token')
      ? Response.json({
          access_token: fakeJwt({ sub: 'u1', roles: [] }),
          id_token: fakeJwt({ sub: 'u1', email: 'a@b.co' }),
          refresh_token: 'r1',
          token_type: 'Bearer',
          expires_in: 900,
        })
      : new Response('', { status: 404 });

  async function startLogin(query: string, cookie?: string) {
    const { GET } = handlersWith(() => new Response(''));
    const res = await GET(
      new Request(`https://app.test/api/auth/login${query}`, cookie ? { headers: { cookie } } : {}),
    );
    const location = new URL(res.headers.get('location')!);
    const flowCookie = setCookies(res).find((c) => c.startsWith(`${FLOW_COOKIE}.`));
    const cookieHeader = flowCookie?.split(';')[0];
    const flow = cookieHeader
      ? await unseal<{ state: string; next: string; silent?: string }>(
          Object.values(parseCookies(cookieHeader))[0]!,
          SECRET,
        )
      : null;
    const state = location.searchParams.get('state');
    if (flow) flow.next = (await nextOfState(state, SECRET))!;
    return { res, location, cookieHeader, flow, state };
  }

  async function callback(query: string, cookie: string, handler = tokenOk) {
    const { GET } = handlersWith(handler);
    return GET(new Request(`https://app.test/api/auth/callback${query}`, { headers: { cookie } }));
  }

  const markCookie = (res: Response) =>
    setCookies(res).find((c) => c.startsWith(`${SILENT_CHECK_COOKIE}=`));

  it('login по умолчанию сначала идёт тихо: prompt=none, PKCE/state и next в auth_flow', async () => {
    const { location, flow, state } = await startLogin('?next=/dashboard');
    expect(location.origin + location.pathname).toBe('https://auth.test/authorize');
    expect(location.searchParams.get('prompt')).toBe('none');
    expect(location.searchParams.get('code_challenge')).toBeTruthy();
    expect(flow!.state.split('~')[0]).toBe(state!.split('~')[0]);
    expect(flow!.next).toBe('/dashboard');
    expect(flow!.silent).toBe('then-interactive');
  });

  it.each(['?next=/x', '?next=/x&silent=1'])(
    'метка ставится уже при старте тихого шага (%s)',
    async (query) => {
      const { res } = await startLogin(query);
      expect(markCookie(res)).toContain('Max-Age=300');
    },
  );

  it('обычный вход (silent=0) метку не ставит', async () => {
    const { res } = await startLogin('?next=/x&silent=0');
    expect(markCookie(res)).toBeUndefined();
  });

  it('next сохраняет query', async () => {
    const { flow } = await startLogin(`?next=${encodeURIComponent('/dash?tab=2')}`);
    expect(flow!.next).toBe('/dash?tab=2');
  });

  it('login?silent=0 — сразу обычный вход, без prompt', async () => {
    const { location, flow } = await startLogin('?next=/dashboard&silent=0');
    expect(location.searchParams.has('prompt')).toBe(false);
    expect(flow!.silent).toBeUndefined();
  });

  it('метка «тихая проверка сделана» не отменяет тихий шаг явного входа (T15)', async () => {
    const { location, flow } = await startLogin('?next=/dashboard', MARK);
    expect(location.searchParams.get('prompt')).toBe('none');
    expect(flow!.silent).toBe('then-interactive');
  });

  it('login?silent=1 — только тихая проверка', async () => {
    const { location, flow } = await startLogin('?next=/&silent=1');
    expect(location.searchParams.get('prompt')).toBe('none');
    expect(flow!.silent).toBe('only');
  });

  it('login?silent=1 с меткой -> сразу назад на next, на сервис не ходим', async () => {
    const { res, location, cookieHeader } = await startLogin('?next=/home&silent=1', MARK);
    expect(res.status).toBe(302);
    expect(location.toString()).toBe('https://app.test/home');
    expect(cookieHeader).toBeUndefined();
  });

  it('тихий вход удался: code -> сессия, сразу на next, метка снята', async () => {
    const { cookieHeader, state } = await startLogin('?next=/dashboard');
    const res = await callback(`?code=c&state=${state}`, `${cookieHeader}; ${MARK}`);
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('https://app.test/dashboard');
    expect(setCookies(res).find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toContain('Max-Age=2592000');
    expect(markCookie(res)).toContain('Max-Age=0');
  });

  it.each(['login_required', 'interaction_required', 'consent_required'])(
    '%s после тихой проверки -> обычный вход с новым PKCE и тем же next (метка уже стоит)',
    async (error) => {
      const { cookieHeader, state, res: loginRes } = await startLogin('?next=/dashboard');
      expect(markCookie(loginRes)).toContain('HttpOnly');
      const res = await callback(`?error=${error}&state=${state}`, cookieHeader!);
      expect(res.status).toBe(302);
      const loc = new URL(res.headers.get('location')!);
      expect(loc.origin + loc.pathname).toBe('https://auth.test/authorize');
      expect(loc.searchParams.has('prompt')).toBe(false);
      expect(loc.searchParams.get('state')).not.toBe(state);

      const flowCookie = setCookies(res).find((c) => c.startsWith(`${FLOW_COOKIE}.`) && !c.includes('Max-Age=0'))!;
      const flow = await unseal<{ state: string; next: string; silent?: string }>(
        Object.values(parseCookies(flowCookie.split(';')[0]!))[0]!,
        SECRET,
      );
      expect(flow!.state.split('~')[0]).toBe(loc.searchParams.get('state')!.split('~')[0]);
      expect(await nextOfState(loc.searchParams.get('state'), SECRET)).toBe('/dashboard');
      expect(flow!.silent).toBeUndefined();
      expect(setCookies(res).find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBeUndefined();
    },
  );

  it('login_required после silent=1 -> метка и назад на next, без интерактивного входа', async () => {
    const { cookieHeader, state } = await startLogin('?next=/home&silent=1');
    const res = await callback(`?error=login_required&state=${state}`, cookieHeader!);
    expect(res.headers.get('location')).toBe('https://app.test/home');
    expect(markCookie(res)).toContain('Max-Age=300');
    expect(setCookies(res).find((c) => c.startsWith(`${FLOW_COOKIE}.`))).toContain('Max-Age=0');
  });

  it('ошибка с чужим state -> страница ошибки, метку не трогает', async () => {
    const { cookieHeader } = await startLogin('?next=/dashboard');
    const res = await callback('?error=login_required&state=ЧУЖОЙ', cookieHeader!);
    expectErrorPage(res);
    expect(markCookie(res)).toBeUndefined();
  });

  it('прочая ошибка тихой проверки -> страница ошибки', async () => {
    const { cookieHeader, state } = await startLogin('?next=/dashboard');
    const res = await callback(`?error=server_error&state=${state}`, cookieHeader!);
    expectErrorPage(res);
  });

  it('ошибка обычного входа не запускает вход заново (нет цикла)', async () => {
    const { cookieHeader, state } = await startLogin('?next=/dashboard&silent=0');
    const res = await callback(`?error=login_required&state=${state}`, cookieHeader!);
    expectErrorPage(res);
  });

  it('страница ошибки: «Попробовать снова» ведёт на обычный вход с тем же next', async () => {
    const { cookieHeader, state } = await startLogin(`?next=${encodeURIComponent('/d?a=1&b="x"')}&silent=0`);
    const res = await callback(`?error=access_denied&state=${state}`, cookieHeader!);
    const html = await res.text();
    expect(html).toContain('Попробовать снова');
    // next нормализован: кавычки в query закодированы.
    expect(html).toContain(`href="/api/auth/login?silent=0&amp;next=${encodeURIComponent('/d?a=1&b=%22x%22')}"`);
    expect(html).not.toContain('"x"');
  });

  it('сбой callback у уже вошедшего -> как раньше на / (сессия жива, круга нет)', async () => {
    const { seal } = await import('../../module/server/core/cookie-seal.js');
    const session = await seal(
      { user: { id: 'u1', roles: [] }, accessToken: 'a', refreshToken: 'r1', accessTokenExpiresAt: Date.now() + 1e6 },
      SECRET,
    );
    const res = await callback('?code=c&state=старый', `${SESSION_COOKIE}=${session}`);
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('https://app.test/');
  });

  it('silent=1 и сбой обмена кода -> тихо назад на next', async () => {
    const { cookieHeader, state } = await startLogin('?next=/home&silent=1');
    const res = await callback(`?code=c&state=${state}`, cookieHeader!, async () =>
      Response.json({ error: 'invalid_grant' }, { status: 400 }),
    );
    expect(res.headers.get('location')).toBe('https://app.test/home');
  });

  it('cookie отключены: silent=1 возвращает на next с меткой в адресе', async () => {
    const { state } = await startLogin(`?next=${encodeURIComponent('/blog?x=1')}&silent=1`);
    const res = await callback(`?error=login_required&state=${state}`, '');
    expect(res.headers.get('location')).toBe(`https://app.test/blog?x=1&${SILENT_CHECK_PARAM}=1`);
  });

  it('cookie отключены: обычный/тихий-с-входом -> страница ошибки', async () => {
    const { state } = await startLogin('?next=/dashboard');
    const res = await callback(`?error=login_required&state=${state}`, '');
    expectErrorPage(res);
  });

  it('подделанный state без auth_flow не уводит на чужой адрес', async () => {
    const forged = `abc.o.${btoa('//evil.com').replace(/=+$/, '')}`;
    const res = await callback(`?error=login_required&state=${forged}`, '');
    const loc = res.headers.get('location');
    if (loc) expect(new URL(loc).origin).toBe('https://app.test');
  });
});

describe('подтверждённый POST /api/auth/logout', () => {
  it('отзывает refresh, чистит session, редиректит на /logout сервиса', async () => {
    // Сначала соберём валидную session cookie напрямую через seal.
    const { seal } = await import('../../module/server/core/cookie-seal.js');
    const session = await seal(
      { user: { id: 'u1', roles: [] }, accessToken: 'a', refreshToken: 'r1', accessTokenExpiresAt: Date.now() + 1e6 },
      SECRET,
    );
    let revoked: any = null;
    const handlers = handlersWith(async (req) => {
      if (req.url.endsWith('/oauth/revoke')) {
        revoked = await req.json();
        return new Response(null, { status: 200 });
      }
      return new Response('');
    });
    const res = await confirmLogout((req) => req.method === 'POST' ? handlers.POST(req) : handlers.GET(req), 'https://app.test', `${SESSION_COOKIE}=${session}`);
    expect(revoked).toEqual({ token: 'r1' });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get('location')!);
    expect(loc.origin + loc.pathname).toBe('https://auth.test/logout');
    expect(loc.searchParams.get('post_logout_redirect_uri')).toBe('https://app.test/');
    expect(setCookies(res).find((c) => c.startsWith(`${SESSION_COOKIE}=`))).toContain('Max-Age=0');
    expect(setCookies(res).find((c) => c.startsWith(`${SILENT_CHECK_COOKIE}=`))).toContain('Max-Age=0');
  });
});

describe('GET /api/auth/me', () => {
  it('валидная сессия -> { user }', async () => {
    const { seal } = await import('../../module/server/core/cookie-seal.js');
    const session = await seal(
      { user: { id: 'u1', roles: ['admin'] }, accessToken: 'a', refreshToken: 'r1', accessTokenExpiresAt: Date.now() + 1e6 },
      SECRET,
    );
    const { GET } = handlersWith(() => new Response(''));
    const res = await GET(
      new Request('https://app.test/api/auth/me', { headers: { cookie: `${SESSION_COOKIE}=${session}` } }),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: { id: 'u1', roles: ['admin'] } });
  });

  // Ответ «кто я» зависит от cookie: кэш браузера или прокси не должен
  // показать одному человеку чужой или устаревший ответ.
  it('ответ с пользователем и без него -> cache-control: no-store', async () => {
    const { seal } = await import('../../module/server/core/cookie-seal.js');
    const session = await seal(
      { user: { id: 'u1', roles: [] }, accessToken: 'a', refreshToken: 'r1', accessTokenExpiresAt: Date.now() + 1e6 },
      SECRET,
    );
    const { GET } = handlersWith(() => new Response(''));
    const withUser = await GET(
      new Request('https://app.test/api/auth/me', { headers: { cookie: `${SESSION_COOKIE}=${session}` } }),
    );
    const anonymous = await GET(new Request('https://app.test/api/auth/me'));
    expect(withUser.headers.get('cache-control')).toBe('no-store');
    expect(anonymous.headers.get('cache-control')).toBe('no-store');
  });

  // Сервер Node у Hono (@hono/node-server) дописывает Content-Length прямо в
  // объект заголовков, переданный в new Response. Общий на все ответы объект
  // унёс бы длину одного ответа в следующий — и прокси оборвал бы ответ.
  it('каждый ответ — со своими заголовками: длина одного не попадает в другой', async () => {
    class MutatingResponse extends Response {
      constructor(body?: BodyInit | null, init?: ResponseInit) {
        super(body, init);
        const h = init?.headers;
        if (h && !(h instanceof Headers) && !Array.isArray(h) && typeof body === 'string')
          (h as Record<string, string>)['content-length'] ??= String(new TextEncoder().encode(body).length);
      }
    }
    vi.stubGlobal('Response', MutatingResponse);
    try {
      const { seal } = await import('../../module/server/core/cookie-seal.js');
      const session = await seal(
        { user: { id: 'u1', roles: [] }, accessToken: 'a', refreshToken: 'r1', accessTokenExpiresAt: Date.now() + 1e6 },
        SECRET,
      );
      const { GET } = handlersWith(() => new Response(''));
      await GET(new Request('https://app.test/api/auth/me'));
      const res = await GET(
        new Request('https://app.test/api/auth/me', { headers: { cookie: `${SESSION_COOKIE}=${session}` } }),
      );
      const length = res.headers.get('content-length');
      if (length !== null) expect(Number(length)).toBe(new TextEncoder().encode(await res.text()).length);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('нет сессии -> 401', async () => {
    const { GET } = handlersWith(() => new Response(''));
    const res = await GET(new Request('https://app.test/api/auth/me'));
    expect(res.status).toBe(401);
  });

  // Метка тихой проверки — HttpOnly-cookie, фронт её не видит. Ответ «кто я»
  // сообщает, была ли проверка, чтобы фронт не ушёл в круг тихого входа.
  it('нет сессии -> 401 сообщает, что тихой проверки ещё не было', async () => {
    const { GET } = handlersWith(() => new Response(''));
    const res = await GET(new Request('https://app.test/api/auth/me'));
    expect(await res.json()).toEqual({ error: 'unauthenticated', silentChecked: false });
  });

  it('нет сессии, есть метка тихой проверки -> 401 с silentChecked: true', async () => {
    const { GET } = handlersWith(() => new Response(''));
    const res = await GET(
      new Request('https://app.test/api/auth/me', { headers: { cookie: `${SILENT_CHECK_COOKIE}=1` } }),
    );
    expect(await res.json()).toEqual({ error: 'unauthenticated', silentChecked: true });
  });
});

describe('неизвестное действие', () => {
  it('-> 404', async () => {
    const { GET } = handlersWith(() => new Response(''));
    const res = await GET(new Request('https://app.test/api/auth/unknown'));
    expect(res.status).toBe(404);
  });
});
