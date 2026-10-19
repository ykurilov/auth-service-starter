import type { FastifyInstance } from 'fastify';
import type { HttpDeps } from '../../../src/adapters/http/deps.js';
import type { Config } from '../../../src/config/config.js';
import type { SsoStores } from '../../../src/domain/sso/sso-session.js';
import type { Client } from '../../../src/domain/clients/client.js';
import { fakeClock } from '../../helpers/fake-clock.js';
import pino from 'pino';
import { loadSigningKey } from '../../../src/domain/tokens/signing-key.js';
import { TokenService } from '../../../src/domain/tokens/token-service.js';
import { LoginService } from '../../../src/domain/login/login-service.js';
import { AuthorizationCodeService } from '../../../src/domain/login/authorization-code-service.js';
import { SessionService } from '../../../src/domain/sessions/session-service.js';
import { IdentityService } from '../../../src/domain/identity/identity-service.js';
import { EmailCodeProvider } from '../../../src/domain/email-login/email-code-provider.js';
import { InMemoryIdentityRepository } from '../../../src/adapters/repository/in-memory-identity-repository.js';
import { InMemoryClientRegistry } from '../../../src/adapters/repository/in-memory-client-registry.js';
import { InMemoryAuthorizationCodeStore } from '../../../src/adapters/repository/in-memory-authorization-code-store.js';
import { InMemoryClientLock } from '../../../src/adapters/repository/in-memory-client-lock.js';
import { InMemoryLoginChallengeStore } from '../../../src/adapters/repository/in-memory-login-challenge-store.js';
import { InMemorySessionStore } from '../../../src/adapters/repository/in-memory-session-store.js';
import { InMemoryRefreshTokenStore } from '../../../src/adapters/repository/in-memory-refresh-token-store.js';
import { InMemorySsoSessionStore, inMemorySsoStores } from '../../../src/adapters/repository/in-memory-sso-session-store.js';
import { SsoSessionService } from '../../../src/domain/sso/sso-session-service.js';
import { FakeMailer } from '../../../src/adapters/mail/fake-mailer.js';
import { computeS256Challenge } from '../../../src/domain/login/pkce.js';
import { InMemoryRateLimiter } from '../../../src/adapters/ratelimit/in-memory-rate-limiter.js';
import type { RateLimits } from '../../../src/config/config.js';

export const TEST_VERIFIER = 'phase3d-token-verifier-достаточно-длинный-1234567890';
export const TEST_CHALLENGE = computeS256Challenge(TEST_VERIFIER);

// CSRF форм входа (double-submit): в браузере значение приходит из csrf-cookie
// и дублируется скрытым полем формы. В тестах фиксируем одно значение и кладём
// его и в cookie (FORM_HEADERS), и в поле формы (authorizeForm/локальные form()).
export const TEST_CSRF = 'csrf-test-token';
// Заголовки формы другого браузера (своя csrf-cookie).
export function browserHeaders(csrf: string): Record<string, string> {
  return { 'content-type': 'application/x-www-form-urlencoded', cookie: `csrf=${csrf}` };
}

export const FORM_HEADERS = {
  'content-type': 'application/x-www-form-urlencoded',
  cookie: `csrf=${TEST_CSRF}`,
} as const;

export function authorizeForm(extra: Record<string, string>): string {
  return new URLSearchParams({
    client_id: 'app',
    redirect_uri: 'https://app.example/cb',
    code_challenge: TEST_CHALLENGE,
    code_challenge_method: 'S256',
    scope: 'openid profile email',
    state: 'st1',
    csrf: TEST_CSRF,
    ...extra,
  }).toString();
}

const ISSUER = 'https://auth.example';
const DEFAULT_CLIENT: Client = {
  id: 'app',
  type: 'external',
  redirectUris: ['https://app.example/cb'],
  allowedProviders: ['email'],
};

export interface TestDeps extends HttpDeps {
  mailer: FakeMailer;
  repo: InMemoryIdentityRepository;
  codeProvider: EmailCodeProvider;
  // Хранилища SSO и сессий приложений (тест подменяет методы для сбоев).
  ssoStores: SsoStores;
}

// handle попытки входа по коду из HTML экрана ввода кода (скрытое поле challenge).
export function extractChallenge(html: string): string {
  const m = /name="challenge" value="([^"]+)"/.exec(html);
  if (!m) throw new Error('на странице нет попытки входа (поле challenge)');
  return m[1]!;
}

// Шаг identify: отправляет код на адрес и возвращает handle попытки.
export async function startCodeLogin(
  app: FastifyInstance,
  email: string,
  extra: Record<string, string> = {},
  headers: Record<string, string> = FORM_HEADERS,
): Promise<string> {
  const res = await app.inject({
    method: 'POST',
    url: '/authorize/identify',
    payload: authorizeForm({ email, ...extra }),
    headers,
  });
  if (res.statusCode !== 200) throw new Error(`identify: статус ${res.statusCode}`);
  return extractChallenge(res.body);
}

export async function makeTestDeps(opts?: {
  clients?: Client[];
  fixedCode?: string;
  // Последовательность кодов (каждая отправка берёт следующий) — для проверки
  // замены кода при переотправке. Приоритетнее fixedCode.
  codeSequence?: string[];
  // Частичный override лимитов: спец-тесты задают низкие пороги, чтобы
  // упереться в 429 за пару запросов; остальные поля берутся из дефолтов.
  rateLimits?: Partial<RateLimits>;
  // Токен Admin API. По умолчанию undefined — роут /admin/clients не монтируется,
  // прочие тесты его не задевают. Admin-тест передаёт свой токен.
  adminApiToken?: string;
  // Число доверенных прокси-хопов. По умолчанию 0 (req.ip = адрес сокета).
  // Тест защиты за прокси ставит 1, чтобы req.ip брался из X-Forwarded-For.
  trustProxy?: number;
}): Promise<TestDeps> {
  const clock = fakeClock(new Date('2026-07-02T00:00:00Z'));
  const defaultRateLimits: RateLimits = {
    identifyPerIp: { limit: 60, windowSeconds: 900 },
    googleNoncePerIp: { limit: 300, windowSeconds: 900 },
    codeRequest: { limit: 4, windowSeconds: 900 },
    codeRequestPerEmail: { limit: 8, windowSeconds: 3600 },
    codeRequestPerIp: { limit: 20, windowSeconds: 3600 },
    codeRequestPerEmailDaily: { limit: 20, windowSeconds: 86400 },
    codeVerifyPerIp: { limit: 30, windowSeconds: 900 },
    token: { limit: 60, windowSeconds: 900 },
    revoke: { limit: 60, windowSeconds: 900 },
  };
  const config: Config = {
    port: 3016,
    issuerUrl: ISSUER,
    keyAutogenerate: true,
    accessTtlSeconds: 900,
    idTtlSeconds: 900,
    refreshTtlSeconds: 2592000,
    clients: opts?.clients ?? [DEFAULT_CLIENT],
    migrateOnBoot: true,
    ssoTtlSeconds: 2592000,
    ssoCookieName: 'sso',
    csrfCookieName: 'csrf',
    ssoCookieSecure: false,
    trustProxy: opts?.trustProxy ?? 0,
    logLevel: 'silent',
    emailAppName: 'Auth Service',
    adminApiToken: opts?.adminApiToken,
    rateLimits: { ...defaultRateLimits, ...opts?.rateLimits },
  };
  const repo = new InMemoryIdentityRepository(clock);
  const identity = new IdentityService(repo);
  const codeStore = new InMemoryAuthorizationCodeStore();
  const codes = new AuthorizationCodeService(codeStore, clock, 60);
  // Один и тот же реестр используется LoginService и роутом /logout — так тесты
  // видят те же клиенты (redirectUris, postLogoutRedirectUris) в обоих местах.
  const clients = new InMemoryClientRegistry(opts?.clients ?? [DEFAULT_CLIENT]);
  const login = new LoginService(clients, identity, codes);
  const signingKey = await loadSigningKey({ autogenerate: true });
  const tokens = new TokenService(signingKey, [signingKey], clock, {
    issuer: ISSUER,
    accessTtlSeconds: 900,
    idTtlSeconds: 900,
  });
  const refreshTokens = new InMemoryRefreshTokenStore();
  const sessionStore = new InMemorySessionStore(refreshTokens);
  const sessions = new SessionService(
    sessionStore,
    refreshTokens,
    tokens,
    clock,
    { refreshTtlSeconds: 2592000 },
  );
  const mailer = new FakeMailer();
  const challengeStore = new InMemoryLoginChallengeStore();
  const codeProvider = new EmailCodeProvider(challengeStore, mailer, clock, {
    appName: config.emailAppName,
    codeTtlMinutes: 15,
    generateCode: () => opts?.codeSequence?.shift() ?? opts?.fixedCode ?? 'CODE55',
  });
  const ssoSessionStore = new InMemorySsoSessionStore();
  const ssoStores = inMemorySsoStores(ssoSessionStore, sessionStore);
  const sso = new SsoSessionService(ssoStores, clock, {
    ssoTtlSeconds: config.ssoTtlSeconds,
  });
  const logger = pino({ level: 'silent' });
  return {
    config,
    logger,
    login,
    codes,
    sessions,
    tokens,
    signingKey,
    signingKeys: [signingKey],
    codeProvider,
    identity: repo,
    sso,
    clients,
    // Тот же in-memory-реестр обслуживает и Admin API (он реализует ClientWriteStore).
    adminClients: clients,
    clientLock: new InMemoryClientLock(clients, { codes, sessions, sso: ssoSessionStore },
      (clientId) => codeStore.invalidateForClient(clientId, clock.now())),
    rateLimiter: new InMemoryRateLimiter(clock),
    otpRateLimiter: new InMemoryRateLimiter(clock),
    mailer,
    repo,
    ssoStores,
  };
}

// Вход по коду для тестов: единственный способ завести пользователя и получить
// authorization code. identify (отправка кода) → code/verify (обмен на код).
// fixedCode фабрики по умолчанию 'CODE55', поэтому verify детерминирован без
// чтения письма. extra подмешивается в обе формы (напр. nonce для id_token).
// Возвращает выданный authorization code из редиректа.
export async function loginWithCode(
  app: FastifyInstance,
  opts: { email?: string; code?: string; extra?: Record<string, string> } = {},
): Promise<string> {
  const email = opts.email ?? 'user@x.com';
  const code = opts.code ?? 'CODE55';
  const extra = opts.extra ?? {};
  const challenge = await startCodeLogin(app, email, extra);
  const res = await app.inject({
    method: 'POST',
    url: '/authorize/code/verify',
    payload: authorizeForm({ challenge, code, ...extra }),
    headers: FORM_HEADERS,
  });
  const location = res.headers['location'] as string | undefined;
  if (!location)
    throw new Error(`ожидался редирект с кодом, получен статус ${res.statusCode}`);
  const issued = new URL(location).searchParams.get('code');
  if (!issued) throw new Error('в редиректе нет authorization code');
  return issued;
}
