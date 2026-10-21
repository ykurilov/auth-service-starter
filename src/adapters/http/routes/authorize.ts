import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Logger } from 'pino';
import { z } from 'zod';
import type { Config, RateLimitRule } from '../../../config/config.js';
import { MailDeliveryError } from '../../../ports/mailer.js';
import type { HttpDeps } from '../deps.js';
import type { AuthenticatedLogin, AuthorizationRequest } from '../../../domain/login/login-service.js';
import { loginPage } from '../views/login-page.js';
import { consentPage } from '../views/consent-page.js';
import { errorPage, type ErrorPageBack } from '../views/error-page.js';
import { authorizeUrl, type OidcParams } from '../views/oidc-params.js';
import { setSsoCookie, readSsoCookie, readBindingCookie, setBindingCookie } from '../cookies.js';
import { ensureCsrf, isSameOriginRequest, readCsrfCookie, verifyCsrf } from '../csrf.js';
import { enforce, ipHash, sendTooManyAttempts, waitText } from '../rate-limit.js';
import { logSecurityEvent } from '../security-log.js';
import { parseEmailAddress } from '../../../domain/identity/user.js';
import { EmailOwnershipRequiredError } from '../../../domain/identity/identity-service.js';
import type { ProviderIdentity } from '../../../domain/identity/provider-identity.js';
import type { PendingLink } from '../../../domain/email-login/login-challenge.js';
import {
  ChallengeClientChangedError,
  InvalidCredentialsError,
  InvalidEmailError,
  UnconfirmedCodeDeliveryError,
} from '../../../domain/email-login/errors.js';
import { displayEmail, toAsciiEmail } from '../../../domain/email-login/email-address.js';
import { EMAIL_PROVIDER } from '../../../domain/email-login/email-provider.js';
import {
  InvalidClientError,
  InvalidRedirectUriError,
  ProviderNotAllowedError,
  UnsupportedPkceError,
} from '../../../domain/login/errors.js';
import { GOOGLE_PROVIDER } from '../../../domain/google-login/google-provider.js';
import type { ValidatedAuthorization } from '../../../domain/login/login-service.js';

const querySchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().min(1),
  response_type: z.string().optional(),
  // Без PKCE запрос не пройдёт, но отказ — после проверки client_id и
  // redirect_uri: тогда он уходит клиенту редиректом invalid_request.
  code_challenge: z.string().default(''),
  code_challenge_method: z.string().default(''),
  scope: z.string().default('openid'),
  state: z.string().optional(),
  nonce: z.string().optional(),
  prompt: z.string().optional(),
});

// OIDC-параметры формы входа + CSRF. От него — конкретные схемы шагов.
const formSchema = z.object({
  client_id: z.string(),
  redirect_uri: z.string(),
  code_challenge: z.string(),
  code_challenge_method: z.string(),
  scope: z.string().default('openid'),
  state: z.string().optional(),
  nonce: z.string().optional(),
  csrf: z.string(),
});

// Первый шаг «Получить код»: адрес почты (строгая проверка — в обработчике).
const identifySchema = formSchema.extend({ email: z.string().min(1).max(320) });
// Переотправка и проверка кода — в рамках попытки: её handle из скрытого поля.
// email_hint — адрес для подстановки в поле почты, если попытка уже истекла.
const codeRequestSchema = formSchema.extend({
  challenge: z.string().min(1).max(200),
  email_hint: z.string().max(320).optional(),
});
const codeVerifySchema = codeRequestSchema.extend({ code: z.string().min(1).max(32) });
// Вход через Google: OIDC-параметры + ID Token (credential) от GIS-виджета.
const googleSchema = formSchema.extend({ credential: z.string().min(1) });
// Согласие (consent): OIDC-параметры + CSRF + пользователь, которому показан
// экран. Нет поля (старая страница) — как несовпадение: экран покажут заново.
const confirmSchema = formSchema.extend({ expected_user: z.string().max(200).optional() });

export function redirectWithCode(
  reply: FastifyReply,
  redirectUri: string,
  code: string,
  state?: string,
): FastifyReply {
  return reply.redirect(authorizationCallbackUrl(redirectUri, code, state), 302);
}

function authorizationCallbackUrl(redirectUri: string, code: string, state?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set('code', code);
  if (state !== undefined) url.searchParams.set('state', state);
  return url.toString();
}

function wantsReplaceNavigation(req: FastifyRequest): boolean {
  return req.headers['x-auth-navigation'] === 'replace';
}

function replaceNavigation(reply: FastifyReply, redirectTo: string): FastifyReply {
  return reply.status(200).header('cache-control', 'no-store').send({ redirectTo });
}

export function toAuthorizationRequest(p: OidcParams): AuthorizationRequest {
  return {
    clientId: p.client_id,
    redirectUri: p.redirect_uri,
    codeChallenge: p.code_challenge,
    codeChallengeMethod: p.code_challenge_method,
    scope: p.scope,
    state: p.state,
    nonce: p.nonce,
  };
}

export function html(reply: FastifyReply, status: number, body: string): FastifyReply {
  return reply
    .status(status)
    .header('content-type', 'text/html; charset=utf-8')
    .header('cache-control', 'no-store')
    .send(body);
}

// Единая точка отказа для POST-форм входа: чужой origin или нет валидной
// csrf-пары — нейтральная страница-ошибка, до любых обращений к хранилищам и
// провайдерам. Значение csrf-cookie дальше служит привязкой к браузеру.
function csrfGuard(
  req: FastifyRequest, reply: FastifyReply, config: Config, field: unknown, params: OidcParams,
): string | null {
  const cookie = readCsrfCookie(req, config);
  if (cookie !== null && isSameOriginRequest(req, config) && verifyCsrf(req, config, field)) return cookie;
  html(reply, 400, errorPage(
    'Некорректный запрос',
    'Сессия формы истекла. Вернитесь ко входу и начните заново.',
    backToSignIn(params),
  ));
  return null;
}

// Ссылка «ко входу» с теми же параметрами: сам /authorize проверит их заново.
// prompt=login — сразу ввод почты, SSO-cookie не уведёт на экран согласия.
function backToSignIn(params: OidcParams): ErrorPageBack {
  return { href: authorizeUrl(params, true), label: 'Вернуться ко входу' };
}

// RFC 6749 §4.1.2.1: ошибка возвращается клиенту редиректом на redirect_uri.
// error_description по спеке — только ASCII.
function errorCallbackUrl(redirectUri: string, error: string, description: string, state?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  url.searchParams.set('error_description', description);
  if (state !== undefined) url.searchParams.set('state', state);
  return url.toString();
}

export function redirectWithError(
  reply: FastifyReply,
  redirectUri: string,
  error: string,
  description: string,
  state?: string,
): FastifyReply {
  return reply.redirect(errorCallbackUrl(redirectUri, error, description, state), 302);
}

export function authorizeErrorPage(err: unknown, reply: FastifyReply, logger?: Logger): FastifyReply {
  if (err instanceof InvalidClientError)
    return html(reply, 400, errorPage('Некорректный запрос', 'Неизвестное приложение'));
  if (err instanceof InvalidRedirectUriError)
    return html(reply, 400, errorPage('Некорректный запрос', 'Недопустимый redirect_uri'));
  // Не-доменная ошибка = сбой инфраструктуры: пользователю нейтральная
  // страница, а причина — в лог, иначе сбой останется невидимым.
  logger?.error({ err }, 'сбой в /authorize-флоу');
  return html(reply, 500, errorPage('Ошибка сервера', 'Попробуйте позже'));
}

// Развилка ошибок /authorize. UnsupportedPkceError и ProviderNotAllowedError
// бросаются только после проверки client_id + redirect_uri (порядок жёстко
// задан в validateRequest/completeLogin), поэтому по спеке их положено
// возвращать редиректом с error=, а не HTML-страницей — иначе OIDC-библиотеки
// (openid-client, oidc-client-ts) виснут по таймауту вместо обработки ошибки.
// JS-форма кода (X-Auth-Navigation: replace) получает тот же адрес в JSON:
// fetch не может пройти редирект на чужой origin.
function authorizeError(
  err: unknown,
  req: FastifyRequest,
  reply: FastifyReply,
  params: OidcParams,
  logger?: Logger,
): FastifyReply {
  const protocolError =
    err instanceof UnsupportedPkceError
      ? { error: 'invalid_request', description: 'PKCE code_challenge (43-128 base64url characters) with method S256 is required' }
      : err instanceof ProviderNotAllowedError
        ? { error: 'unauthorized_client', description: 'login method is not allowed for this client' }
        : null;
  if (!protocolError) return authorizeErrorPage(err, reply, logger);
  const url = errorCallbackUrl(params.redirect_uri, protocolError.error, protocolError.description, params.state);
  return wantsReplaceNavigation(req) ? replaceNavigation(reply, url) : reply.redirect(url, 302);
}

// Почтовый провайдер не принял письмо или не ответил вовремя (таймаут в
// адаптере). Пользователь остаётся на своём шаге и может повторить.
const MAIL_FAILED = 'Не удалось отправить письмо с кодом. Попробуйте ещё раз через минуту.';
// Первое письмо попытки не подтвердилось: при таймауте оно могло всё же
// дойти позже, поэтому пользователь остаётся на экране кода этой попытки,
// и код из этого письма действует.
const MAIL_UNCONFIRMED =
  'Не удалось подтвердить отправку письма. Если письмо всё же придёт, введите код из него. ' +
  'Если нет — нажмите «Отправить код ещё раз».';
// То же для повторного письма: его код уже заменил прежний.
const MAIL_UNCONFIRMED_RESEND =
  'Не удалось подтвердить отправку нового письма, а прежний код больше не действует. ' +
  'Если письмо всё же придёт, введите код из него. Если нет — нажмите «Отправить код ещё раз».';
// Форму почты отправили ещё раз (двойное нажатие, «Назад», обновление
// страницы), пока у браузера есть живая попытка на этот адрес.
const CODE_ALREADY_SENT = 'Код уже отправили на этот адрес — введите его из письма.';
// Код уже погашен, а вход не завершился (сбой хранилища): тот же код больше
// не подойдёт.
const LOGIN_NOT_COMPLETED = 'Не удалось завершить вход. Код уже использован — начните вход заново.';
// Попытка начата у прежней регистрации приложения (его удалили и создали
// заново) — продолжать её нельзя.
const CLIENT_CHANGED = 'Приложение изменилось, пока шёл вход. Начните вход заново.';

export function registerAuthorize(app: FastifyInstance, deps: HttpDeps): void {
  const otp = deps.otpRateLimiter;

  // Кнопка Google рендерится только когда провайдер собран (GOOGLE_CLIENT_ID
  // задан) и клиент допущен к нему в allowedProviders. Вместе с кнопкой сервер
  // выпускает одноразовый nonce, хранит его у себя (привязка к браузеру и
  // клиенту) и гасит при входе — повтор того же id_token не пройдёт.
  // Выпуск nonce ограничен по источнику своим счётчиком (в production общий
  // Pg-счётчик держит предел и при сбое Redis). Лимит исчерпан — вместо кнопки
  // Google пояснение со временем ожидания: вход по почте nonce не нужен.
  const googleFields = async (
    req: FastifyRequest,
    validated: ValidatedAuthorization,
    binding: string,
  ): Promise<{ googleClientId?: string; googleNonce?: string; googleUnavailableFor?: string }> => {
    if (
      !deps.googleProvider ||
      !deps.googleNonces ||
      !deps.config.googleClientId ||
      !validated.client.allowedProviders.includes(GOOGLE_PROVIDER)
    ) {
      return {};
    }
    const rule = deps.config.rateLimits.googleNoncePerIp;
    const hit = await otp.hit(`google-nonce:${ipHash(req)}`, rule.limit, rule.windowSeconds);
    if (!hit.allowed) return { googleUnavailableFor: waitText(hit.retryAfterSeconds) };
    return {
      googleClientId: deps.config.googleClientId,
      googleNonce: await deps.googleNonces.issue(binding, validated.client.id),
    };
  };

  // Первый экран входа (адрес почты и кнопка Google).
  const identifyPage = async (
    req: FastifyRequest,
    reply: FastifyReply,
    params: OidcParams,
    validated: ValidatedAuthorization,
    extra: { email?: string; error?: string; notice?: string; status?: number } = {},
  ): Promise<FastifyReply> => {
    const csrfToken = ensureCsrf(req, reply, deps.config);
    return html(
      reply,
      extra.status ?? 200,
      loginPage({
        params,
        csrfToken,
        emailAllowed: validated.client.allowedProviders.includes(EMAIL_PROVIDER),
        ...(extra.email !== undefined ? { email: displayEmail(extra.email) } : {}),
        ...(extra.error !== undefined ? { error: extra.error } : {}),
        ...(extra.notice !== undefined ? { notice: extra.notice } : {}),
        ...(await googleFields(req, validated, csrfToken)),
      }),
    );
  };

  const codePage = (
    req: FastifyRequest,
    reply: FastifyReply,
    params: OidcParams,
    input: { email: string; challenge: string; error?: string; notice?: string },
    status = 200,
  ): FastifyReply =>
    html(
      reply,
      status,
      loginPage({
        params,
        mode: 'code',
        csrfToken: ensureCsrf(req, reply, deps.config),
        ...input,
        email: displayEmail(input.email),
      }),
    );

  // Глобальная SSO-cookie может быть выпущена способом входа, который не
  // разрешён конкретному клиенту. Такая сессия по-прежнему пригодна для
  // других приложений, но для текущего клиента равносильна отсутствующей.
  // Живая сессия скользяще продлевается в хранилище — продлеваем и cookie,
  // иначе браузер выбросил бы её по старому Max-Age раньше сессии. Заодно
  // продлеваем привязку браузера к её цепочке (или выдаём её цепочке,
  // начатой до обновления).
  const resolveCompatibleSsoSession = async (
    req: FastifyRequest,
    reply: FastifyReply,
    validated: ValidatedAuthorization,
  ) => {
    const token = readSsoCookie(req, deps.config);
    const session = token ? await deps.sso.resolve(token) : null;
    if (session && token) {
      setSsoCookie(reply, deps.config, token);
      setBindingCookie(reply, deps.config, await deps.sso.bindBrowser(session, readBindingCookie(req, deps.config)));
    }
    return session && validated.client.allowedProviders.includes(session.auth.provider)
      ? session
      : null;
  };

  // Новая SSO-сессия браузера после входа: продолжает его цепочку (по
  // SSO-cookie или привязке) и обновляет обе cookie.
  const startSsoSession = async (req: FastifyRequest, reply: FastifyReply, login: AuthenticatedLogin) => {
    const started = await deps.sso.start(
      login.userId, login.auth, readSsoCookie(req, deps.config), readBindingCookie(req, deps.config),
    );
    setSsoCookie(reply, deps.config, started.rawToken);
    setBindingCookie(reply, deps.config, started.bindingToken);
  };

  // Вход завершён аутентификацией (код из письма, Google). internal получает
  // код сразу. external — только после экрана согласия: результат входа
  // сохранён SSO-сессией, браузер уходит на /authorize, и тот показывает
  // «Продолжить как …» с названием и адресом приложения (POST
  // /authorize/confirm выдаст код). JS-форма кода получает адрес в JSON.
  const finishLogin = async (
    req: FastifyRequest,
    reply: FastifyReply,
    params: OidcParams,
    validated: ValidatedAuthorization,
    pid: ProviderIdentity,
  ): Promise<FastifyReply> => {
    if (validated.client.type === 'external') {
      await startSsoSession(req, reply, await deps.login.authenticate(validated, pid));
      const consentUrl = authorizeUrl(params);
      return wantsReplaceNavigation(req) ? replaceNavigation(reply, consentUrl) : reply.redirect(consentUrl, 303);
    }
    const login = await deps.login.completeLogin(validated, pid);
    await startSsoSession(req, reply, login);
    const callback = authorizationCallbackUrl(params.redirect_uri, login.code, params.state);
    return wantsReplaceNavigation(req) ? replaceNavigation(reply, callback) : reply.redirect(callback, 302);
  };

  // Бюджеты отправки кода (Postgres-лимитер). Каждое письмо тратит общий
  // бюджет источника на все адреса. Новая попытка входа — ещё и бюджет
  // источника на адрес, паузу между письмами на адрес и суточный потолок
  // адреса (против ротации IP). Переотправка в живой попытке их не тратит:
  // её предел — в самой попытке, и посторонний, занявший бюджет адреса, не
  // мешает владельцу дослать код. Отказ по любому бюджету возвращает уже
  // списанные. Возвращает списанные ключи (чтобы вернуть их, если провайдер
  // отказал); emailPause — адрес на паузе, секунды до нового письма; null —
  // лимит исчерпан и страница 429 уже отправлена.
  const enforceSendBudget = async (
    req: FastifyRequest,
    reply: FastifyReply,
    params: OidcParams,
    email: string,
    send: 'new-attempt' | 'resend',
  ): Promise<{ spent: string[] } | { emailPause: number } | null> => {
    const r = deps.config.rateLimits;
    const ip = ipHash(req);
    const pauseKey = `code-req-email-pause:${email}`;
    const budgets: [string, RateLimitRule][] = [[`code-req-ip:${ip}`, r.codeRequestPerIp]];
    if (send === 'new-attempt')
      budgets.push(
        [`code-req:${ip}:${email}`, r.codeRequest],
        [pauseKey, r.codeRequestEmailPause],
        [`code-req-email-day:${email}`, r.codeRequestPerEmailDaily],
      );
    const spent: string[] = [];
    for (const [key, rule] of budgets) {
      const hit = await otp.hit(key, rule.limit, rule.windowSeconds);
      if (!hit.allowed) {
        await refundSendBudget(spent);
        if (key === pauseKey) return { emailPause: hit.retryAfterSeconds };
        sendTooManyAttempts(reply, hit.retryAfterSeconds, backToSignIn(params));
        return null;
      }
      spent.push(key);
    }
    return { spent };
  };

  // Провайдер окончательно отказал: письма не было, бюджет не списываем.
  const refundSendBudget = async (spent: string[]): Promise<void> => {
    for (const key of spent) await otp.refund?.(key);
  };

  // Новая попытка входа по коду и экран ввода. Наличие аккаунта не раскрываем:
  // код уходит на любой корректный адрес, аккаунт заводится при верном коде.
  // Адрес на паузе, а у этого браузера есть живая попытка на него у этого
  // клиента (форму отправили ещё раз) — экран кода той же попытки без нового
  // письма. Посторонний браузер своей попытки не имеет и получает 429.
  const startCodeLogin = async (
    req: FastifyRequest,
    reply: FastifyReply,
    params: OidcParams,
    validated: ValidatedAuthorization,
    binding: string,
    rawEmail: string,
    link?: PendingLink,
    notice?: string,
  ): Promise<FastifyReply> => {
    const email = parseEmailAddress(toAsciiEmail(rawEmail));
    if (!email)
      return identifyPage(req, reply, params, validated, {
        email: rawEmail,
        error: 'Проверьте адрес почты',
        status: 400,
      });
    const budget = await enforceSendBudget(req, reply, params, email, 'new-attempt');
    if (!budget) return reply;
    if ('emailPause' in budget) {
      const resumed = await deps.codeProvider.resume({ email, binding, client: validated.client, ...(link ? { link } : {}) });
      if (resumed)
        return codePage(req, reply, params, {
          email: resumed.email,
          challenge: resumed.handle,
          notice: notice ?? CODE_ALREADY_SENT,
        });
      reply.header('Retry-After', String(budget.emailPause));
      return identifyPage(req, reply, params, validated, {
        email: rawEmail,
        error: `На этот адрес недавно отправляли код. Новый можно запросить ${waitText(budget.emailPause)}.`,
        status: 429,
      });
    }
    const { spent } = budget;
    let started;
    try {
      started = await deps.codeProvider.start({ email, binding, client: validated.client, ...(link ? { link } : {}) });
    } catch (err) {
      if (err instanceof InvalidEmailError)
        return identifyPage(req, reply, params, validated, { email: rawEmail, error: 'Проверьте адрес почты', status: 400 });
      if (err instanceof UnconfirmedCodeDeliveryError) {
        deps.logger.error({ err }, 'письмо с кодом не подтверждено провайдером');
        return codePage(
          req, reply, params,
          { email: err.challenge.email, challenge: err.challenge.handle, error: MAIL_UNCONFIRMED, ...(notice ? { notice } : {}) },
          503,
        );
      }
      if (err instanceof MailDeliveryError) {
        deps.logger.error({ err }, 'письмо с кодом не отправлено');
        await refundSendBudget(spent);
        return identifyPage(req, reply, params, validated, { email: rawEmail, error: MAIL_FAILED, status: 503 });
      }
      throw err;
    }
    return codePage(req, reply, params, {
      email: started.email,
      challenge: started.handle,
      ...(notice ? { notice } : {}),
    });
  };

  app.get('/authorize', async (req, reply) => {
    const parsed = querySchema.safeParse(req.query);
    if (!parsed.success)
      return html(reply, 400, errorPage('Некорректный запрос', 'Отсутствуют обязательные параметры'));
    // prompt и response_type — управляющие флаги, не часть OIDC-параметров
    // и не попадают в hiddenFields.
    const { prompt, response_type, ...oidc } = parsed.data;
    const params: OidcParams = oidc;
    let validated;
    try {
      validated = await deps.login.validateRequest(toAuthorizationRequest(params));
    } catch (err) {
      return authorizeError(err, req, reply, params, deps.logger);
    }
    // csrf-cookie выдаём уже на тихом шаге (prompt=none): иначе две вкладки,
    // одновременно пришедшие на интерактивный /authorize без cookie, выпустили
    // бы по своему токену, и форма первой вкладки перестала бы проходить.
    ensureCsrf(req, reply, deps.config);
    // Discovery заявляет только code; иной response_type — протокольная ошибка
    // редиректом (redirect_uri к этому моменту уже проверен).
    if (response_type !== undefined && response_type !== 'code')
      return redirectWithError(
        reply, params.redirect_uri, 'unsupported_response_type', 'only response_type=code is supported', params.state,
      );
    if (prompt === 'login') return identifyPage(req, reply, params, validated);
    const session = await resolveCompatibleSsoSession(req, reply, validated);
    if (prompt === 'none') {
      // OIDC Core §3.1.2.1: prompt=none — никакого UI. Живая SSO-сессия есть —
      // тихо выдаём код (silent renew), нет — login_required редиректом.
      if (!session)
        return redirectWithError(
          reply, params.redirect_uri, 'login_required', 'no active session', params.state,
        );
      // Внешнее (независимо управляемое) приложение не получает профиль без
      // явного согласия пользователя: сохранённых согласий сервис не ведёт,
      // поэтому тихий вход для external всегда отвечает consent_required, и
      // приложение показывает обычный вход с экраном «Продолжить как …».
      if (validated.client.type === 'external')
        return redirectWithError(
          reply, params.redirect_uri, 'consent_required', 'user consent is required', params.state,
        );
      try {
        const code = await deps.login.completeSsoLogin(validated, session);
        return redirectWithCode(reply, params.redirect_uri, code, params.state);
      } catch (err) {
        return authorizeError(err, req, reply, params, deps.logger);
      }
    }
    if (session) {
      const csrfToken = ensureCsrf(req, reply, deps.config);
      return html(
        reply,
        200,
        consentPage({ params, email: session.auth.email ?? '', csrfToken, expectedUser: session.userId }),
      );
    }
    return identifyPage(req, reply, params, validated);
  });

  // Вход через Google: страница прислала ID Token из Google Identity Services.
  // Проверка подписи/audience и гашение nonce — в провайдере.
  app.post('/authorize/google', async (req, reply) => {
    const google = deps.googleProvider;
    if (!google)
      return html(reply, 400, errorPage('Вход недоступен', 'Вход через Google не настроен'));
    const parsed = googleSchema.safeParse(req.body);
    if (!parsed.success)
      return html(reply, 400, errorPage('Некорректный запрос', 'Проверьте поля формы'));
    const { csrf, credential, ...rest } = parsed.data;
    const params: OidcParams = rest;
    const binding = csrfGuard(req, reply, deps.config, csrf, params);
    if (binding === null) return;
    if (!(await enforce(deps, reply, `google:${ipHash(req)}`, deps.config.rateLimits.identifyPerIp, undefined, backToSignIn(params))))
      return;
    let validated;
    try {
      validated = await deps.login.validateRequest(toAuthorizationRequest(params));
    } catch (err) {
      return authorizeError(err, req, reply, params, deps.logger);
    }
    let pid: ProviderIdentity;
    try {
      pid = await google.verify({ credential, binding, clientId: validated.client.id });
    } catch (err) {
      if (!(err instanceof InvalidCredentialsError)) return authorizeError(err, req, reply, params, deps.logger);
      logSecurityEvent(deps.logger, req, 'login_failed', { method: 'google' });
      return identifyPage(req, reply, params, validated, {
        error: 'Не удалось войти через Google, попробуйте ещё раз',
      });
    }
    try {
      return await finishLogin(req, reply, params, validated, pid);
    } catch (err) {
      if (!(err instanceof EmailOwnershipRequiredError)) return authorizeError(err, req, reply, params, deps.logger);
      // Google не доказывает владение этим (сторонним) адресом: ни создавать
      // по нему пользователя, ни присоединять к существующему нельзя. Владелец
      // подтверждает адрес кодом из письма; после верного кода эта Google-
      // личность привяжется, и дальше вход через Google будет работать сразу.
      return startCodeLogin(
        req, reply, params, validated, binding, err.email,
        { provider: pid.provider, subject: pid.subject, ...(pid.profile.name ? { name: pid.profile.name } : {}) },
        'Google не подтверждает, что этот адрес принадлежит вам. Введите код из письма — после этого вход через Google будет привязан.',
      );
    }
  });

  // Шаг «Получить код»: единственный способ входа по почте — код из письма.
  app.post('/authorize/identify', async (req, reply) => {
    const parsed = identifySchema.safeParse(req.body);
    if (!parsed.success)
      return html(reply, 400, errorPage('Некорректный запрос', 'Проверьте поля формы'));
    const { csrf, email, ...rest } = parsed.data;
    const params: OidcParams = rest;
    // Токен формы перезаписан другой вкладкой (обе открылись до первой
    // csrf-cookie): с той же страницы сервиса показываем форму заново с
    // действующим токеном и введённым адресом. Сама форма ничего не делает.
    const staleForm =
      readCsrfCookie(req, deps.config) !== null &&
      isSameOriginRequest(req, deps.config) &&
      !verifyCsrf(req, deps.config, csrf);
    const binding = staleForm ? null : csrfGuard(req, reply, deps.config, csrf, params);
    if (!staleForm && binding === null) return;
    let validated;
    try {
      validated = await deps.login.validateRequest(toAuthorizationRequest(params));
    } catch (err) {
      return authorizeError(err, req, reply, params, deps.logger);
    }
    if (binding === null)
      return identifyPage(req, reply, params, validated, {
        email,
        notice: 'Страницу входа открыли в другой вкладке — проверьте адрес и отправьте форму ещё раз',
      });
    if (!validated.client.allowedProviders.includes(EMAIL_PROVIDER))
      return redirectWithError(
        reply, params.redirect_uri, 'unauthorized_client', 'login method is not allowed for this client', params.state,
      );
    return startCodeLogin(req, reply, params, validated, binding, email);
  });

  // Повторная отправка кода в рамках той же попытки (атомарная замена кода).
  app.post('/authorize/code/request', async (req, reply) => {
    const parsed = codeRequestSchema.safeParse(req.body);
    if (!parsed.success)
      return html(reply, 400, errorPage('Некорректный запрос', 'Проверьте поля формы'));
    const { csrf, challenge, email_hint, ...rest } = parsed.data;
    const params: OidcParams = rest;
    const binding = csrfGuard(req, reply, deps.config, csrf, params);
    if (binding === null) return;
    let validated;
    try {
      validated = await deps.login.validateRequest(toAuthorizationRequest(params));
    } catch (err) {
      return authorizeError(err, req, reply, params, deps.logger);
    }
    const view = await deps.codeProvider.describe({ handle: challenge, binding });
    if (!view)
      return identifyPage(req, reply, params, validated, {
        ...(email_hint ? { email: email_hint } : {}),
        error: 'Код истёк или попытки закончились — запросите новый код',
      });
    if (!view.startedFor(validated.client)) return clientChanged(req, reply, params, validated);
    const resendExhausted = () =>
      identifyPage(req, reply, params, validated, {
        email: view.email,
        error: 'Больше отправить код в этой попытке нельзя — начните вход заново',
      });
    // Попытка уже исчерпана (повторы или проверки) — письма не будет, и бюджет
    // отправок не тратим.
    if (view.resendsLeft <= 0 || view.attemptsLeft <= 0) return resendExhausted();
    const budget = await enforceSendBudget(req, reply, params, view.email, 'resend');
    if (!budget) return reply;
    // Переотправка тратит только бюджет источника: паузы адреса у неё нет.
    const spent = 'spent' in budget ? budget.spent : [];
    let resent;
    try {
      resent = await deps.codeProvider.resend({ handle: challenge, binding, client: validated.client });
    } catch (err) {
      if (err instanceof ChallengeClientChangedError) return clientChanged(req, reply, params, validated);
      if (err instanceof UnconfirmedCodeDeliveryError) {
        deps.logger.error({ err }, 'письмо с кодом не подтверждено провайдером');
        return codePage(req, reply, params, { email: view.email, challenge, error: MAIL_UNCONFIRMED_RESEND }, 503);
      }
      if (!(err instanceof MailDeliveryError)) throw err;
      deps.logger.error({ err }, 'письмо с кодом не отправлено');
      if (err.outcome === 'rejected') await refundSendBudget(spent);
      return codePage(req, reply, params, { email: view.email, challenge, error: MAIL_FAILED }, 503);
    }
    if (!resent) return resendExhausted();
    return codePage(req, reply, params, {
      email: resent.email,
      challenge,
      notice: 'Отправили новый код — прежний код больше не действует',
    });
  });

  // Попытка другой регистрации клиента: понятный отказ и путь к новому входу.
  const clientChanged = (
    req: FastifyRequest,
    reply: FastifyReply,
    params: OidcParams,
    validated: ValidatedAuthorization,
  ): Promise<FastifyReply> | FastifyReply => {
    if (wantsReplaceNavigation(req))
      return reply
        .status(409)
        .header('cache-control', 'no-store')
        .send({ error: CLIENT_CHANGED, restartTo: authorizeUrl(params, true) });
    return identifyPage(req, reply, params, validated, { error: CLIENT_CHANGED, status: 409 });
  };

  // Неверный код или исчерпанная попытка.
  const wrongCode = async (
    req: FastifyRequest,
    reply: FastifyReply,
    params: OidcParams,
    validated: ValidatedAuthorization,
    challenge: string,
    binding: string,
    emailHint?: string,
  ): Promise<FastifyReply> => {
    const view = await deps.codeProvider.describe({ handle: challenge, binding });
    logSecurityEvent(deps.logger, req, 'login_failed', {
      method: 'email_code',
      ...(view ? { email: view.email } : {}),
    });
    const message =
      view && view.attemptsLeft > 0
        ? 'Неверный или просроченный код'
        : 'Код истёк или попытки закончились — запросите новый код';
    const exhausted = !view || view.attemptsLeft <= 0;
    // JS-режим: при исчерпанной попытке форма кода бесполезна — сигнал
    // вернуться к вводу почты (prompt=login, чтобы SSO-cookie не увела на
    // экран согласия).
    if (wantsReplaceNavigation(req))
      return reply
        .status(401)
        .header('cache-control', 'no-store')
        .send(exhausted ? { error: message, restartTo: authorizeUrl(params, true) } : { error: message });
    if (exhausted)
      return identifyPage(req, reply, params, validated, {
        ...(view ? { email: view.email } : emailHint ? { email: emailHint } : {}),
        error: message,
      });
    return codePage(req, reply, params, { email: view.email, challenge, error: message });
  };

  app.post('/authorize/code/verify', async (req, reply) => {
    const parsed = codeVerifySchema.safeParse(req.body);
    if (!parsed.success)
      return html(reply, 400, errorPage('Некорректный запрос', 'Проверьте поля формы'));
    const { csrf, challenge, code, email_hint, ...rest } = parsed.data;
    const params: OidcParams = rest;
    const binding = csrfGuard(req, reply, deps.config, csrf, params);
    if (binding === null) return;
    // Общий бюджет неверных кодов одного источника на все попытки и адреса.
    // Списываем до проверки (параллельный перебор не обгонит предел) и
    // возвращаем, если код оказался не неверным: класс за одним IP не тратит
    // бюджет на успешные входы. Лимит каждой попытки (5 проверок) — в её
    // записи; лимита по адресу нет, чтобы посторонний не мог заблокировать
    // вход владельцу.
    const verifyBudgetKey = `code-vrf-ip:${ipHash(req)}`;
    if (!(await enforce(deps, reply, verifyBudgetKey, deps.config.rateLimits.codeVerifyPerIp, otp, backToSignIn(params))))
      return;
    let wrongCodeCharged = false;
    const verifyCode = async () => {
      let validated;
      try {
        validated = await deps.login.validateRequest(toAuthorizationRequest(params));
      } catch (err) {
        return authorizeError(err, req, reply, params, deps.logger);
      }
      // Политика клиента — до гашения кода и попытки: запрещённый способ входа
      // не должен тратить код, проверку и бюджет отправки.
      const pending = await deps.codeProvider.describe({ handle: challenge, binding });
      if (pending && !pending.startedFor(validated.client)) return clientChanged(req, reply, params, validated);
      const provider = pending?.link ? pending.link.provider : EMAIL_PROVIDER;
      if (pending && !validated.client.allowedProviders.includes(provider))
        return authorizeError(new ProviderNotAllowedError(provider), req, reply, params, deps.logger);
      let verified;
      try {
        verified = await deps.codeProvider.verifyChallenge({ handle: challenge, binding, code, client: validated.client });
      } catch (err) {
        if (err instanceof ChallengeClientChangedError) return clientChanged(req, reply, params, validated);
        if (!(err instanceof InvalidCredentialsError)) return authorizeError(err, req, reply, params, deps.logger);
        wrongCodeCharged = true;
        return wrongCode(req, reply, params, validated, challenge, binding, email_hint);
      }
      // Попытка начата входом через Google со сторонним адресом: код доказал
      // владение — входим этой Google-личностью, IdentityService привяжет её
      // к владельцу адреса (или создаст его).
      const pid: ProviderIdentity = verified.link
        ? {
            provider: verified.link.provider,
            subject: verified.link.subject,
            email: verified.identity.email,
            emailVerified: true,
            profile: verified.link.name ? { name: verified.link.name } : {},
          }
        : verified.identity;
      try {
        return await finishLogin(req, reply, params, validated, pid);
      } catch (err) {
        if (err instanceof UnsupportedPkceError || err instanceof ProviderNotAllowedError)
          return authorizeError(err, req, reply, params, deps.logger);
        // Код уже погашен: прямо говорим, что нужен новый вход.
        deps.logger.error({ err }, 'вход по коду не завершён после верного кода');
        if (wantsReplaceNavigation(req))
          return reply
            .status(500)
            .header('cache-control', 'no-store')
            .send({ error: LOGIN_NOT_COMPLETED, restartTo: authorizeUrl(params, true) });
        return identifyPage(req, reply, params, validated, { error: LOGIN_NOT_COMPLETED, status: 500 });
      }
    };
    try {
      return await verifyCode();
    } finally {
      if (!wrongCodeCharged) await otp.refund?.(verifyBudgetKey);
    }
  });

  // «Отказаться» на экране согласия: приложение получает access_denied на
  // проверенный redirect_uri. Код не выдаётся, SSO-сессия остаётся.
  app.post('/authorize/deny', async (req, reply) => {
    const parsed = formSchema.safeParse(req.body);
    if (!parsed.success)
      return html(reply, 400, errorPage('Некорректный запрос', 'Проверьте поля формы'));
    const { csrf, ...rest } = parsed.data;
    const params: OidcParams = rest;
    if (csrfGuard(req, reply, deps.config, csrf, params) === null) return;
    try {
      await deps.login.validateRequest(toAuthorizationRequest(params));
    } catch (err) {
      return authorizeError(err, req, reply, params, deps.logger);
    }
    return redirectWithError(reply, params.redirect_uri, 'access_denied', 'the user denied the request', params.state);
  });

  app.post('/authorize/confirm', async (req, reply) => {
    const parsed = confirmSchema.safeParse(req.body);
    if (!parsed.success)
      return html(reply, 400, errorPage('Некорректный запрос', 'Проверьте поля формы'));
    const { csrf, expected_user, ...rest } = parsed.data;
    const params: OidcParams = rest;
    if (csrfGuard(req, reply, deps.config, csrf, params) === null) return;
    let validated;
    try {
      validated = await deps.login.validateRequest(toAuthorizationRequest(params));
    } catch (err) {
      return authorizeError(err, req, reply, params, deps.logger);
    }
    const session = await resolveCompatibleSsoSession(req, reply, validated);
    if (!session) return identifyPage(req, reply, params, validated);
    // Экран показывали другому пользователю (в соседней вкладке сменили
    // аккаунт): код не выдаём, а возвращаем на /authorize — там согласие
    // покажут заново уже с текущим аккаунтом.
    if (expected_user !== session.userId) return reply.redirect(authorizeUrl(params), 303);
    try {
      const code = await deps.login.completeSsoLogin(validated, session);
      return redirectWithCode(reply, params.redirect_uri, code, params.state);
    } catch (err) {
      return authorizeError(err, req, reply, params, deps.logger);
    }
  });
}
