import { loadModuleConfig, type LoadConfigOptions } from './core/config.js';
import { OidcClient } from './core/oidc-client.js';
import { createSessionManager } from './core/session-manager.js';
import { temporaryUnavailable } from './session-guard.js';
import { createPkce } from './core/pkce.js';
import { seal, unseal } from './core/cookie-seal.js';
import { buildSessionData, isSessionData } from './core/session-data.js';
import {
  SESSION_COOKIE,
  cookieName,
  SILENT_CHECK_PARAM,
  MAX_LOGIN_FLOWS,
  LOGOUT_COOKIE,
  FLOW_COOKIE,
  SESSION_MAX_AGE,
  FLOW_MAX_AGE,
  SILENT_CHECK_COOKIE,
  SILENT_CHECK_MAX_AGE,
  serializeCookie,
  clearCookie,
  parseCookies,
  isSecureAppUrl,
} from './cookies.js';

// Режим тихой проверки (prompt=none) в текущем входе:
// then-interactive — не вышло тихо, сразу обычный вход;
// only — не вышло тихо, вернуть на next (страница покажет «Войти»).
// Нет поля — обычный интерактивный вход (так же читаются auth_flow старых версий).
type SilentMode = 'then-interactive' | 'only';

interface FlowState {
  verifier: string;
  state: string;
  next: string;
  silent?: SilentMode;
}

// Ответы на prompt=none, означающие «без участия пользователя нельзя».
const INTERACTION_ERRORS = new Set([
  'login_required',
  'interaction_required',
  'consent_required',
  'account_selection_required',
]);

// next принимаем только как относительный путь внутри приложения — защита от
// открытого редиректа. Всё, что не начинается с одиночного '/', заменяем на '/'.
function safeNext(raw: string | null): string {
  if (!raw || new TextEncoder().encode(raw).length > 1024) return '/';
  if (!raw.startsWith('/') || raw.startsWith('//') || /[\\\x00-\x20]/.test(raw)) return '/';
  return raw;
}

// Страница сбоя входа. Сама вход не запускает: редирект на защищённую
// страницу снова отправил бы на вход, и получился бы круг. «Попробовать
// снова» — обычный вход по нажатию пользователя.
function errorPage(next: string, cookies: string[]): Response {
  const retry = `/api/auth/login?silent=0&amp;next=${encodeURIComponent(next)}`;
  const html =
    '<!doctype html><html lang="ru"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>Не удалось войти</title></head>' +
    '<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">' +
    '<h1>Не удалось войти</h1>' +
    '<p>Если ошибка повторяется, проверьте, что в браузере разрешены cookie.</p>' +
    `<p><a href="${retry}">Попробовать снова</a> · <a href="/">На главную</a></p>` +
    '</body></html>';
  const headers = new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  for (const c of cookies) headers.append('set-cookie', c);
  return new Response(html, { status: 400, headers });
}

function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ location, 'cache-control': 'no-store' });
  for (const c of cookies) headers.append('set-cookie', c);
  return new Response(null, { status: 302, headers });
}

export function createAuthHandlers(options: LoadConfigOptions = {}) {
  const config = loadModuleConfig(options);
  const client = new OidcClient(config);
  const resolve = createSessionManager(options);
  const secureApp = isSecureAppUrl(config.appUrl);
  const name = (base: string) => cookieName(base, secureApp);
  const flowName = (state: string | null): string | null => {
    const id = state?.split('~')[0];
    return id && /^[A-Za-z0-9_-]{22}$/.test(id) ? `${name(FLOW_COOKIE)}.${id}` : null;
  };
  async function flowCleanup(cookieHeader: string | null): Promise<string[] | null> {
    const expired: string[] = [];
    let active = 0;
    for (const [key, value] of Object.entries(parseCookies(cookieHeader))) {
      if (!key.startsWith(`${name(FLOW_COOKIE)}.`)) continue;
      const flow = await unseal<FlowState>(value, config.cookieSecret);
      if (flow && typeof flow.state === 'string' && flowName(flow.state) === key) active++;
      else expired.push(clearCookie(key, secureApp));
    }
    return active >= MAX_LOGIN_FLOWS ? null : expired;
  }

  async function GET(request: Request): Promise<Response> {
    if (request.method !== 'GET') return new Response(null, { status: 405, headers: { allow: 'GET' } });
    const url = new URL(request.url);
    const action = url.pathname.split('/').filter(Boolean).pop();
    const secure = isSecureAppUrl(config.appUrl);

    if (action === 'login') return login(request, url, secure);
    if (action === 'callback') return callback(request, url, secure);
    if (action === 'logout') return logoutConfirmation(secure);
    if (action === 'me') return me(request);
    return new Response('Not found', { status: 404 });
  }

  // /api/auth/login?next=/x — по умолчанию сначала тихая проверка SSO, при
  // неудаче сразу обычный вход. ?silent=1 — только тихая проверка, ?silent=0 —
  // сразу обычный вход. Метка «тихая проверка сделана» отменяет тихий шаг.
  async function login(request: Request, url: URL, secure: boolean): Promise<Response> {
    const next = safeNext(url.searchParams.get('next'));
    const param = url.searchParams.get('silent');
    const checked = parseCookies(request.headers.get('cookie'))[name(SILENT_CHECK_COOKIE)] !== undefined;
    if (param === '1' && checked) return redirect(`${config.appUrl}${next}`);
    const cleanup = await flowCleanup(request.headers.get('cookie'));
    if (!cleanup) return new Response('Слишком много попыток входа. Завершите одну из открытых вкладок или повторите через 10 минут.', {
      status: 429, headers: { 'cache-control': 'no-store', 'retry-after': String(FLOW_MAX_AGE) },
    });
    if (param === '1') {
      return startFlow(next, secure, 'only', cleanup);
    }
    if (param === '0' || checked) return startFlow(next, secure, undefined, cleanup);
    return startFlow(next, secure, 'then-interactive', cleanup);
  }

  // Метку ставим уже на старте тихого шага, а снимаем только при успешном
  // входе: любой сбой по дороге (обмен кода, протухший auth_flow) оставит её,
  // и повторного тихого захода по кругу не будет.
  async function startFlow(next: string, secure: boolean, silent?: SilentMode, cleanup: string[] = []): Promise<Response> {
    const pkce = await createPkce();
    // Для silent=1 next дублируем в state (запечатанным): если cookie в
    // браузере отключены и auth_flow не дошла, callback всё равно вернёт
    // пользователя на страницу с меткой в адресе, а не по кругу.
    const state = silent === 'only' ? `${pkce.state}~${await seal({ next }, config.cookieSecret, FLOW_MAX_AGE)}` : pkce.state;
    const flow: FlowState = { verifier: pkce.verifier, state, next };
    if (silent) flow.silent = silent;
    const sealed = await seal(flow, config.cookieSecret, FLOW_MAX_AGE);
    const cookies = [...cleanup, serializeCookie(flowName(state)!, sealed, { maxAgeSeconds: FLOW_MAX_AGE, secure })];
    if (silent) cookies.push(silentMark(secure));
    return redirect(
      client.buildAuthorizeUrl({
        challenge: pkce.challenge,
        state,
        ...(silent ? { prompt: 'none' as const } : {}),
      }),
      cookies,
    );
  }

  function silentMark(secure: boolean): string {
    return serializeCookie(SILENT_CHECK_COOKIE, '1', { maxAgeSeconds: SILENT_CHECK_MAX_AGE, secure });
  }

  // next из state тихой проверки silent=1 — только если печать цела.
  async function silentOnlyNext(state: string | null): Promise<string | null> {
    const idx = state?.indexOf('~') ?? -1;
    if (!state || idx === -1) return null;
    const data = await unseal<{ next?: unknown }>(state.slice(idx + 1), config.cookieSecret);
    return typeof data?.next === 'string' ? safeNext(data.next) : null;
  }

  async function hasSession(cookies: Record<string, string>): Promise<boolean> {
    const sealed = cookies[name(SESSION_COOKIE)];
    const data = sealed ? await unseal(sealed, config.cookieSecret) : null;
    return isSessionData(data) && data.accessTokenExpiresAt > Date.now();
  }

  async function callback(request: Request, url: URL, secure: boolean): Promise<Response> {
    const cookies = parseCookies(request.headers.get('cookie'));
    const state = url.searchParams.get('state');
    const key = flowName(state);
    // Чужой/malformed state не стирает ни одной попытки.
    let clearFlow: string[] = [];
    // Любой сбой — страница ошибки с чисткой ТОЛЬКО auth_flow, без деталей
    // наружу. auth_session не трогаем: иначе подброшенная ссылка на
    // /api/auth/callback?error=x разлогинивала бы уже вошедшего пользователя.
    // Уже вошедшего (повтор старого callback) просто ведём на /, как раньше.
    const fail = async (next = '/') =>
      (await hasSession(cookies)) ? redirect(`${config.appUrl}/`, clearFlow) : errorPage(next, clearFlow);

    const sealed = key ? cookies[key] : undefined;
    const flow = sealed ? await unseal<FlowState>(sealed, config.cookieSecret) : null;
    // Свой вход — только если state сошёлся с запечатанным в auth_flow.
    const ownFlow = flow && state && state === flow.state && typeof flow.verifier === 'string' && /^[A-Za-z0-9_-]{43,128}$/.test(flow.verifier) && typeof flow.next === 'string' && safeNext(flow.next) === flow.next && (flow.silent === undefined || flow.silent === 'only' || flow.silent === 'then-interactive') ? flow : null;
    if (ownFlow && key) clearFlow = [clearCookie(key, secure)];

    if (!ownFlow) {
      // auth_flow не дошла (cookie отключены или истекли), а это была тихая
      // проверка silent=1: возвращаем на страницу с меткой в адресе.
      const quietNext = await silentOnlyNext(state);
      if (quietNext === null) return fail();
      const target = new URL(quietNext, config.appUrl);
      target.searchParams.set(SILENT_CHECK_PARAM, '1');
      return redirect(target.toString(), clearFlow);
    }

    const next = ownFlow.next;
    // silent=1: любой сбой тихий — назад на страницу, она покажет «Войти».
    const giveUp = () =>
      ownFlow.silent === 'only' ? redirect(`${config.appUrl}${next}`, [...clearFlow, silentMark(secure)]) : fail(next);

    const error = url.searchParams.get('error');
    if (error) {
      // Тихо не вышло, нужен пользователь — обычный вход. Ошибка обычного
      // входа новый вход не запускает — так не бывает круга.
      if (ownFlow.silent === 'then-interactive' && INTERACTION_ERRORS.has(error))
        return startFlow(next, secure, undefined, clearFlow);
      return giveUp();
    }

    const code = url.searchParams.get('code');
    if (!code) return giveUp();

    try {
      const tokens = await client.exchangeCode({ code, verifier: ownFlow.verifier });
      const data = buildSessionData({ ...tokens, now: new Date() });
      if (!data) return giveUp();
      const session = await seal(data, config.cookieSecret);
      return redirect(`${config.appUrl}${next}`, [
        serializeCookie(SESSION_COOKIE, session, { maxAgeSeconds: SESSION_MAX_AGE, secure }),
        ...clearFlow,
        clearCookie(SILENT_CHECK_COOKIE, secure),
      ]);
    } catch {
      return giveUp();
    }
  }

  async function logout(request: Request, secure: boolean): Promise<Response> {
    const cookies = parseCookies(request.headers.get('cookie'));
    const sealed = cookies[name(SESSION_COOKIE)];
    if (sealed) {
      const data = await unseal(sealed, config.cookieSecret);
      if (isSessionData(data)) await client.revoke(data.refreshToken);
    }
    return redirect(client.buildLogoutUrl(), [
      clearCookie(SESSION_COOKIE, secure),
      clearCookie(SILENT_CHECK_COOKIE, secure),
    ]);
  }

  // GET сохраняет понятную ссылку, но не меняет состояние входа.
  async function logoutConfirmation(secure: boolean): Promise<Response> {
    const token = await seal({ intent: 'logout' }, config.cookieSecret, FLOW_MAX_AGE);
    return new Response('<!doctype html><html lang="ru"><meta charset="utf-8"><title>Выход</title>' +
      '<h1>Выйти из аккаунта?</h1><form method="post" action="/api/auth/logout">' +
      `<input type="hidden" name="csrf" value="${token}"><button type="submit">Выйти</button></form>` +
      '<p><a href="/">Отмена</a></p></html>', {
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
        'content-security-policy': "frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
        'set-cookie': serializeCookie(LOGOUT_COOKIE, token, { maxAgeSeconds: FLOW_MAX_AGE, secure }) },
    });
  }

  async function POST(request: Request): Promise<Response> {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/api/auth/logout')
      return new Response(null, { status: 405, headers: { allow: 'GET' } });
    if (request.headers.get('origin') !== config.appUrl || request.headers.get('sec-fetch-site') === 'cross-site')
      return new Response('Forbidden', { status: 403 });
    let csrf: FormDataEntryValue | null;
    try { csrf = (await request.formData()).get('csrf'); }
    catch { return new Response('Bad request', { status: 400 }); }
    const expected = parseCookies(request.headers.get('cookie'))[name(LOGOUT_COOKIE)];
    const data = typeof csrf === 'string' && csrf === expected
      ? await unseal<{ intent?: string }>(csrf, config.cookieSecret) : null;
    if (data?.intent !== 'logout') return new Response('Forbidden', { status: 403 });
    const res = await logout(request, secureApp);
    res.headers.append('set-cookie', clearCookie(LOGOUT_COOKIE, secureApp));
    // Не оставляем активные login flow, способные восстановить сессию после выхода.
    for (const key of Object.keys(parseCookies(request.headers.get('cookie')))) {
      if (key.startsWith(`${name(FLOW_COOKIE)}.`)) res.headers.append('set-cookie', clearCookie(key, secureApp));
    }
    return res;
  }

  async function me(request: Request): Promise<Response> {
    const result = await resolve(request.headers.get('cookie'));
    if (result.kind === 'unavailable') return temporaryUnavailable();
    const headers = new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' });
    for (const line of result.setCookies) headers.append('set-cookie', line);
    if (result.kind === 'active') return new Response(JSON.stringify({ user: result.data.user }), { headers });
    const silentChecked = parseCookies(request.headers.get('cookie'))[name(SILENT_CHECK_COOKIE)] !== undefined;
    return new Response(JSON.stringify({ error: 'unauthenticated', silentChecked }), { status: 401, headers });
  }

  return { GET, POST };
}
