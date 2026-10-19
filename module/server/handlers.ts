import { loadModuleConfig, type LoadConfigOptions } from './core/config.js';
import { OidcClient } from './core/oidc-client.js';
import { createSessionManager, sharedRetiredRefreshTokens, type RetiredRefreshTokens } from './core/session-manager.js';
import { temporaryUnavailable } from './session-guard.js';
import { createPkce } from './core/pkce.js';
import { seal, unseal } from './core/cookie-seal.js';
import { buildSessionData, type SessionData } from './core/session-data.js';
import { readSession, sessionCookie } from './core/session-cookie.js';
import {
  authCookieNames,
  SILENT_CHECK_PARAM,
  MAX_LOGIN_FLOWS,
  FLOW_MAX_AGE,
  LOGOUT_MAX_AGE,
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

// state — привязка к state из адреса (см. stateBinding): next лежит
// запечатанным в самом state и в cookie не дублируется, поэтому cookie попытки
// не растёт вместе с next. next в cookie — только у попыток прежних версий.
// at — время старта: сверх лимита попыток вытесняется самая старая.
interface FlowState {
  verifier: string;
  state: string;
  next?: string;
  at?: number;
  silent?: SilentMode;
}

// Запечатанная часть state. only — тихая проверка silent=1: её next годится
// для возврата и без cookie попытки. У state прежних версий only нет, и
// запечатанный next был только у silent=1.
interface StateNext {
  next: string;
  only?: boolean;
}

// Ответы на prompt=none, означающие «без участия пользователя нельзя».
const INTERACTION_ERRORS = new Set([
  'login_required',
  'interaction_required',
  'consent_required',
  'account_selection_required',
]);

const MAX_NEXT_BYTES = 2048;
const byteLength = (s: string) => new TextEncoder().encode(s).length;

// state — «<случайная часть>~<запечатанный next>». В cookie попытки кладём
// случайную часть и SHA-256 хвоста: state сверяется целиком, а cookie не
// растёт вместе с next.
async function stateBinding(state: string): Promise<string> {
  const idx = state.indexOf('~');
  if (idx === -1) return state;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(state.slice(idx + 1))));
  let bin = '';
  for (const b of digest) bin += String.fromCharCode(b);
  return `${state.slice(0, idx)}~${btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
}
// next принимаем только как относительный путь внутри приложения — защита от
// открытого редиректа. Всё, что не начинается с одиночного '/', заменяем на '/'.
// Путь нормализуем и кодируем: /кабинет становится /%D0%BA..., иначе сырые
// символы попали бы в заголовок Location, а он принимает только ASCII.
// Слишком длинный next сокращаем до пути страницы без query и fragment.
function safeNext(raw: string | null): string {
  if (!raw || !raw.startsWith('/') || raw.startsWith('//') || /[\\\x00-\x20]/.test(raw)) return '/';
  let url: URL;
  try { url = new URL(raw, 'http://app.invalid'); } catch { return '/'; }
  if (url.origin !== 'http://app.invalid' || url.pathname.startsWith('//')) return '/';
  const next = url.pathname + url.search + url.hash;
  if (byteLength(next) <= MAX_NEXT_BYTES) return next;
  return byteLength(url.pathname) <= MAX_NEXT_BYTES ? url.pathname : '/';
}

const TOO_LARGE_SESSION = 'Данных вашего аккаунта (например, ролей) слишком много: браузер не сохранит такую сессию. ' +
  'Повтор не поможет — сообщите об ошибке администратору приложения.';

// Страница сбоя входа. Сама вход не запускает: редирект на защищённую
// страницу снова отправил бы на вход, и получился бы круг. «Попробовать
// снова» — обычный вход по нажатию пользователя.
function errorPage(next: string, cookies: string[], reason = 'Если ошибка повторяется, проверьте, что в браузере разрешены cookie.'): Response {
  const retry = `/api/auth/login?silent=0&amp;next=${encodeURIComponent(next)}`;
  const html =
    '<!doctype html><html lang="ru"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>Не удалось войти</title></head>' +
    '<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">' +
    '<h1>Не удалось войти</h1>' +
    `<p>${reason}</p>` +
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

// retired — реестр сессий, закрытых выходом или новым входом. По умолчанию
// общий на процесс для client_id: его видят и guard, и middleware Next.js.
export function createAuthHandlers(options: LoadConfigOptions = {}, retiredOverride?: RetiredRefreshTokens) {
  const config = loadModuleConfig(options);
  const retired = retiredOverride ?? sharedRetiredRefreshTokens(config.clientId);
  const client = new OidcClient(config);
  const resolve = createSessionManager(options, retired);
  const secureApp = isSecureAppUrl(config.appUrl);
  const names = authCookieNames(config.clientId, config.appUrl);
  const FLOW_ID = /^[A-Za-z0-9_-]{22}$/;
  const flowName = (state: string | null): string | null => {
    const id = state?.split('~')[0];
    return id && FLOW_ID.test(id) ? `${names.flow}.${id}` : null;
  };
  // Своя попытка — только точное имя `${names.flow}.<22 символа>`: у соседа с
  // client_id вида «наш.что-то» хвост длиннее и с точкой.
  const isOwnFlowCookie = (key: string) =>
    key.startsWith(`${names.flow}.`) && FLOW_ID.test(key.slice(names.flow.length + 1));
  // Свои попытки входа из cookie запроса: протухшие стираем. Перед стартом
  // новой (starting) стираем и самые старые живые сверх лимита, чтобы с новой
  // их было не больше MAX_LOGIN_FLOWS: брошенные вкладки не блокируют вход.
  async function flowCleanup(cookieHeader: string | null, starting: boolean): Promise<string[]> {
    const cleared: string[] = [];
    const active: { key: string; at: number }[] = [];
    for (const [key, value] of Object.entries(parseCookies(cookieHeader))) {
      if (!isOwnFlowCookie(key)) continue;
      const flow = await unseal<FlowState>(value, config.cookieSecret);
      if (flow && typeof flow.state === 'string' && flowName(flow.state) === key)
        active.push({ key, at: Number.isFinite(flow.at) ? flow.at! : 0 });
      else cleared.push(clearCookie(key, secureApp));
    }
    active.sort((a, b) => a.at - b.at);
    const excess = starting ? active.length - (MAX_LOGIN_FLOWS - 1) : 0;
    for (const { key } of active.slice(0, Math.max(0, excess)))
      cleared.push(clearCookie(key, secureApp));
    return cleared;
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
  // сразу обычный вход. Метка «тихая проверка сделана» отменяет только
  // silent=1: явный вход всё равно сначала пробует тихо — пользователь мог
  // войти в соседнее приложение, и тогда экран входа не нужен. Круга нет:
  // неудачная тихая попытка сразу переходит к обычному входу.
  async function login(request: Request, url: URL, secure: boolean): Promise<Response> {
    const next = safeNext(url.searchParams.get('next'));
    const param = url.searchParams.get('silent');
    const checked = parseCookies(request.headers.get('cookie'))[names.silentCheck] !== undefined;
    if (param === '1' && checked) return redirect(`${config.appUrl}${next}`, await flowCleanup(request.headers.get('cookie'), false));
    const cleanup = await flowCleanup(request.headers.get('cookie'), true);
    if (param === '1') return startFlow(next, secure, 'only', cleanup);
    if (param === '0') return startFlow(next, secure, undefined, cleanup);
    return startFlow(next, secure, 'then-interactive', cleanup);
  }

  // Метку ставим уже на старте тихого шага, а снимаем только при успешном
  // входе: любой сбой по дороге (обмен кода, протухший auth_flow) оставит её,
  // и повторного тихого захода по кругу не будет.
  async function startFlow(next: string, secure: boolean, silent?: SilentMode, cleanup: string[] = []): Promise<Response> {
    const pkce = await createPkce();
    const key = flowName(pkce.state)!;
    // next едет в state запечатанным. Для silent=1 он годится и без cookie
    // попытки: если cookie в браузере отключены, callback всё равно вернёт
    // пользователя на страницу с меткой в адресе, а не по кругу.
    const payload: StateNext = { next, only: silent === 'only' };
    const state = `${pkce.state}~${await seal(payload, config.cookieSecret, FLOW_MAX_AGE)}`;
    const flow: FlowState = { verifier: pkce.verifier, state: await stateBinding(state), at: Date.now() };
    if (silent) flow.silent = silent;
    const sealed = await seal(flow, config.cookieSecret, FLOW_MAX_AGE);
    const cookies = [...cleanup, serializeCookie(key, sealed, { maxAgeSeconds: FLOW_MAX_AGE, secure })];
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

  // Возврат после тихой проверки с меткой в адресе: работает и без cookie.
  function silentReturn(next: string): string {
    const target = new URL(next, config.appUrl);
    target.searchParams.set(SILENT_CHECK_PARAM, '1');
    return target.toString();
  }

  function silentMark(secure: boolean): string {
    return serializeCookie(names.silentCheck, '1', { maxAgeSeconds: SILENT_CHECK_MAX_AGE, secure });
  }

  // Запечатанная часть state — только если печать цела.
  async function stateNext(state: string | null): Promise<{ next: string; only: boolean } | null> {
    const idx = state?.indexOf('~') ?? -1;
    if (!state || idx === -1) return null;
    const data = await unseal<{ next?: unknown; only?: unknown }>(state.slice(idx + 1), config.cookieSecret);
    return typeof data?.next === 'string' ? { next: data.next, only: data.only !== false } : null;
  }

  function sessionOf(cookies: Record<string, string>): Promise<SessionData | null> {
    return readSession(cookies[names.session], config.cookieSecret);
  }

  async function hasSession(cookies: Record<string, string>): Promise<boolean> {
    const data = await sessionOf(cookies);
    return !!data && data.accessTokenExpiresAt > Date.now();
  }

  // Прежняя сессия закрыта: летящий refresh её токена не выдаст cookie, а
  // сервис отзовёт её токены.
  async function retire(data: SessionData | null): Promise<void> {
    if (!data) return;
    retired.retire(data.refreshToken);
    await client.revoke(data.refreshToken);
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
    const fromState = await stateNext(state);
    // next попыток прежних версий лежит в cookie, новых — в state.
    const flowNext = typeof flow?.next === 'string' ? flow.next : fromState?.next;
    // Свой вход — только если state сошёлся с запечатанным в auth_flow.
    const ownFlow = flow && state && typeof flow.state === 'string' && flow.state === await stateBinding(state) && typeof flow.verifier === 'string' && /^[A-Za-z0-9_-]{43,128}$/.test(flow.verifier) && typeof flowNext === 'string' && safeNext(flowNext) === flowNext && (flow.silent === undefined || flow.silent === 'only' || flow.silent === 'then-interactive') ? flow : null;
    if (ownFlow && key) clearFlow = [clearCookie(key, secure)];

    if (!ownFlow || flowNext === undefined) {
      // auth_flow не дошла (cookie отключены или истекли), а это была тихая
      // проверка silent=1: возвращаем на страницу с меткой в адресе.
      if (!fromState?.only) return fail();
      return redirect(silentReturn(safeNext(fromState.next)), clearFlow);
    }

    const next = flowNext;
    // silent=1: любой сбой тихий — назад на страницу, она покажет «Войти».
    // Сбой своего входа — всегда страница ошибки, даже при живой старой
    // сессии: молча вернуть на неё значило бы скрыть, что вход не удался.
    const giveUp = () =>
      ownFlow.silent === 'only' ? redirect(`${config.appUrl}${next}`, [...clearFlow, silentMark(secure)]) : errorPage(next, clearFlow);

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
      const session = await sessionCookie(names.session, data, config.cookieSecret, secure);
      if (!session) {
        // Браузер молча выбросил бы такую cookie, и вход пошёл бы по кругу.
        // Страница ошибки — даже для тихой проверки, метку не ставим: это
        // не «SSO нет», а ошибка, о которой должен узнать администратор.
        await client.revoke(data.refreshToken);
        return errorPage(next, clearFlow, TOO_LARGE_SESSION);
      }
      const previous = await sessionOf(cookies);
      if (previous?.refreshToken !== data.refreshToken) await retire(previous);
      return redirect(`${config.appUrl}${next}`, [
        session,
        ...clearFlow,
        clearCookie(names.silentCheck, secure),
      ]);
    } catch {
      return giveUp();
    }
  }

  async function logout(request: Request, secure: boolean): Promise<Response> {
    const cookies = parseCookies(request.headers.get('cookie'));
    await retire(await sessionOf(cookies));
    return redirect(client.buildLogoutUrl(), [
      clearCookie(names.session, secure),
      clearCookie(names.silentCheck, secure),
    ]);
  }

  // GET сохраняет понятную ссылку, но не меняет состояние входа.
  async function logoutConfirmation(secure: boolean): Promise<Response> {
    const token = await seal({ intent: 'logout' }, config.cookieSecret, LOGOUT_MAX_AGE);
    return new Response('<!doctype html><html lang="ru"><meta charset="utf-8"><title>Выход</title>' +
      '<h1>Выйти из аккаунта?</h1><form method="post" action="/api/auth/logout">' +
      `<input type="hidden" name="csrf" value="${token}"><button type="submit">Выйти</button></form>` +
      '<p><a href="/">Отмена</a></p></html>', {
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
        'content-security-policy': "frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
        'set-cookie': serializeCookie(names.logout, token, { maxAgeSeconds: LOGOUT_MAX_AGE, secure }) },
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
    const expected = parseCookies(request.headers.get('cookie'))[names.logout];
    const data = typeof csrf === 'string' && csrf === expected
      ? await unseal<{ intent?: string }>(csrf, config.cookieSecret) : null;
    if (data?.intent !== 'logout') return new Response('Forbidden', { status: 403 });
    const res = await logout(request, secureApp);
    res.headers.append('set-cookie', clearCookie(names.logout, secureApp));
    // Не оставляем активные login flow, способные восстановить сессию после выхода.
    for (const key of Object.keys(parseCookies(request.headers.get('cookie')))) {
      if (isOwnFlowCookie(key)) res.headers.append('set-cookie', clearCookie(key, secureApp));
    }
    return res;
  }

  async function me(request: Request): Promise<Response> {
    const result = await resolve(request.headers.get('cookie'));
    if (result.kind === 'unavailable') return temporaryUnavailable();
    const headers = new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' });
    for (const line of result.setCookies) headers.append('set-cookie', line);
    if (result.kind === 'active') return new Response(JSON.stringify({ user: result.data.user }), { headers });
    const silentChecked = parseCookies(request.headers.get('cookie'))[names.silentCheck] !== undefined;
    return new Response(JSON.stringify({ error: 'unauthenticated', silentChecked }), { status: 401, headers });
  }

  return { GET, POST };
}
