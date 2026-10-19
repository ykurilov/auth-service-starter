import { pathToFileURL } from 'node:url';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from './config/config.js';
import { createLogger } from './logging/logger.js';
import {
  loadSigningKey,
  generateSigningKeyPem,
  signingKeyFromPem,
  type SigningKey,
} from './domain/tokens/signing-key.js';
import { TokenService } from './domain/tokens/token-service.js';
import { PgSigningKeyStore } from './adapters/repository/pg/pg-signing-key-store.js';
import { systemClock } from './ports/clock.js';
import { IdentityService } from './domain/identity/identity-service.js';
import { AuthorizationCodeService } from './domain/login/authorization-code-service.js';
import { LoginService } from './domain/login/login-service.js';
import { SessionService } from './domain/sessions/session-service.js';
import type { EmailSecretStore } from './domain/email-secret/email-secret.js';
import type { LoginChallengeStore } from './domain/email-login/login-challenge.js';
import { GoogleNonceService, type GoogleNonceStore } from './domain/google-login/google-nonce.js';
import { InMemoryLoginChallengeStore } from './adapters/repository/in-memory-login-challenge-store.js';
import { InMemoryGoogleNonceStore } from './adapters/repository/in-memory-google-nonce-store.js';
import { PgLoginChallengeStore } from './adapters/repository/pg/pg-login-challenge-store.js';
import { PgGoogleNonceStore } from './adapters/repository/pg/pg-google-nonce-store.js';
import { PgRateLimiter } from './adapters/ratelimit/pg-rate-limiter.js';
import { EmailCodeProvider } from './domain/email-login/email-code-provider.js';
import { GoogleProvider } from './domain/google-login/google-provider.js';
import { createGoogleTokenVerifier } from './adapters/google/google-token-verifier.js';
import { LogMailer } from './adapters/mail/log-mailer.js';
import { createResendMailer } from './adapters/mail/resend-mailer.js';
import type { Mailer } from './ports/mailer.js';
import { InMemoryIdentityRepository } from './adapters/repository/in-memory-identity-repository.js';
import { InMemoryClientRegistry } from './adapters/repository/in-memory-client-registry.js';
import { InMemoryAuthorizationCodeStore } from './adapters/repository/in-memory-authorization-code-store.js';
import { InMemoryEmailSecretStore } from './adapters/repository/in-memory-email-secret-store.js';
import { InMemorySessionStore } from './adapters/repository/in-memory-session-store.js';
import { InMemoryRefreshTokenStore } from './adapters/repository/in-memory-refresh-token-store.js';
import { InMemorySsoSessionStore, inMemorySsoStores } from './adapters/repository/in-memory-sso-session-store.js';
import { SsoSessionService } from './domain/sso/sso-session-service.js';
import { InMemoryRateLimiter } from './adapters/ratelimit/in-memory-rate-limiter.js';
import { createRedisRateLimiter } from './adapters/ratelimit/redis-rate-limiter.js';
import type { RateLimiter } from './ports/rate-limiter.js';
import { buildServer } from './adapters/http/server.js';
import type { HttpDeps } from './adapters/http/deps.js';
import type { Db } from './adapters/db/pool.js';
import { createPool } from './adapters/db/pool.js';
import { runMigrations } from './adapters/db/migrate.js';
import { PgIdentityRepository } from './adapters/repository/pg/pg-identity-repository.js';
import { PgClientRegistry } from './adapters/repository/pg/pg-client-registry.js';
import { PgSessionStore } from './adapters/repository/pg/pg-session-store.js';
import { PgRefreshTokenStore } from './adapters/repository/pg/pg-refresh-token-store.js';
import { PgSsoSessionStore, pgSsoStores } from './adapters/repository/pg/pg-sso-session-store.js';
import { PgAuthorizationCodeStore } from './adapters/repository/pg/pg-authorization-code-store.js';
import { PgClientLock } from './adapters/repository/pg/pg-client-lock.js';
import { InMemoryClientLock } from './adapters/repository/in-memory-client-lock.js';
import type { ClientLock } from './domain/clients/client-lock.js';
import { PgEmailSecretStore } from './adapters/repository/pg/pg-email-secret-store.js';
import { CleanupService } from './domain/maintenance/cleanup-service.js';
import { startCleanupSchedule, type CleanupSchedule } from './domain/maintenance/cleanup-schedule.js';
import type { IdentityRepository } from './domain/identity/identity-repository.js';
import type { ClientRegistry, ClientWriteStore } from './domain/clients/client.js';
import type { SessionStore } from './domain/sessions/session.js';
import type { RefreshTokenStore } from './domain/sessions/refresh-token.js';
import type { SsoSessionStore, SsoStores } from './domain/sso/sso-session.js';
import type { AuthorizationCodeStore } from './domain/login/authorization-code.js';

export interface BootstrapOptions {
  // Позволяет тесту подменить создание Db (иначе bootstrap полез бы в реальный
  // Postgres). По умолчанию — боевой пул через connectionString.
  dbFactory?: (url: string) => Db;
  // Тестовый сид генератора кодов входа: детерминированный код вместо
  // случайного 6-значного. Как и dbFactory, нужен только тестам — прод всегда
  // генерирует случайный код.
  codeGenerator?: () => string;
}

export async function bootstrap(
  env: NodeJS.ProcessEnv = process.env,
  opts?: BootstrapOptions,
) {
  const config = loadConfig(env);
  const logger = createLogger(config.logLevel);
  if (env.NODE_ENV === 'production' && !config.ssoCookieSecure && !['localhost', '127.0.0.1', '[::1]'].includes(new URL(config.issuerUrl).hostname)) {
    throw new Error('Production HTTPS требует SSO_COOKIE_SECURE=true');
  }
  if (env.NODE_ENV === 'production' && (!config.resendApiKey || !config.emailFrom)) {
    throw new Error('Production требует RESEND_API_KEY и EMAIL_FROM для доставки кодов входа');
  }
  if (env.NODE_ENV === 'production' && !config.databaseUrl) {
    throw new Error('Production требует DATABASE_URL для постоянного хранения пользователей и ключей');
  }


  // Ключи подписи: активный (подпись) и полный набор для верификации по kid.
  // Заполняются ниже в зависимости от хранилища — из БД (db-путь) или из
  // конфигурации/автогенерации (in-memory-путь).
  let activeSigningKey: SigningKey;
  let signingKeys: SigningKey[];

  // Выбор хранилищ: при заданном DATABASE_URL — Postgres-адаптеры (источник
  // истины — БД), иначе — прежние in-memory. Порты одни и те же, поэтому
  // доменные сервисы собираются поверх выбранного набора без изменений.
  let db: Db | undefined;
  let identityRepo: IdentityRepository;
  let clientRegistry: ClientRegistry;
  let authCodeStore: AuthorizationCodeStore;
  // Только без БД: гашение кодов клиента для InMemoryClientLock.
  let inMemoryCodeStore: InMemoryAuthorizationCodeStore | undefined;
  let sessionStore: SessionStore;
  let refreshTokenStore: RefreshTokenStore;
  let ssoSessionStore: SsoSessionStore;
  // SSO-сессии вместе с сессиями приложений (смена аккаунта и выход — атомарно).
  let ssoStores: SsoStores;
  let emailSecretStore: EmailSecretStore;
  let loginChallengeStore: LoginChallengeStore;
  let googleNonceStore: GoogleNonceStore;
  // Лимитер кодов из письма: в Postgres (общий для экземпляров), без БД — in-memory.
  let otpRateLimiter: RateLimiter;
  let cleanupSchedule: CleanupSchedule | undefined;

  if (config.databaseUrl) {
    db = opts?.dbFactory
      ? opts.dbFactory(config.databaseUrl)
      : createPool(config.databaseUrl, (err) =>
          logger.error({ err }, 'обрыв соединения с Postgres'),
        );
    // Миграции идут под общей advisory-блокировкой: копии, стартующие
    // одновременно, применяют их по очереди, а не падают друг на друге.
    if (config.migrateOnBoot) {
      const applied = await runMigrations(db, 'migrations');
      logger.info({ applied }, 'migrations applied');
    }
    const registry = new PgClientRegistry(db);
    // CLIENTS_JSON применяется однократно; удаление через Admin API переживает рестарт.
    await registry.seedInitial(config.clients);
    identityRepo = new PgIdentityRepository(db);
    clientRegistry = registry;
    authCodeStore = new PgAuthorizationCodeStore(db);
    sessionStore = new PgSessionStore(db);
    refreshTokenStore = new PgRefreshTokenStore(db);
    ssoSessionStore = new PgSsoSessionStore(db);
    ssoStores = pgSsoStores(db);
    emailSecretStore = new PgEmailSecretStore(db);
    loginChallengeStore = new PgLoginChallengeStore(db);
    googleNonceStore = new PgGoogleNonceStore(db);
    const pgOtpLimiter = new PgRateLimiter(db, systemClock);
    otpRateLimiter = pgOtpLimiter;

    // Ключи подписи — из БД (источник истины, переживают рестарт). Если активного
    // нет (первый запуск) — генерируем и сидируем один. ensureActive устойчив к гонке:
    // при одновременном старте нескольких реплик победит один seed, остальные подхватят
    // его. Верификация — по всем ключам (включая retired), чтобы токены, выпущенные до
    // ротации, проверялись.
    const keyStore = new PgSigningKeyStore(db);
    let active = await keyStore.getActive();
    if (!active) {
      const gen = await generateSigningKeyPem();
      const rec = {
        ...gen,
        status: 'active' as const,
        createdAt: new Date(),
        retiredAt: null,
        revokedAt: null,
      };
      active = await keyStore.ensureActive(rec);
    }
    // Отозванные (скомпрометированные) ключи исключаем из набора верификации:
    // токены, подписанные ими, немедленно перестают проходить проверку.
    const stored = (await keyStore.listAll()).filter((s) => s.revokedAt === null);
    signingKeys = await Promise.all(
      stored.map((s) => signingKeyFromPem(s.privatePem, s.publicPem, s.kid)),
    );
    const found = signingKeys.find((k) => k.kid === active!.kid);
    if (!found) throw new Error('active signing key not found among loaded keys');
    activeSigningKey = found;

    // Автоочистка устаревших данных (коды, email-секреты, сессии, sso-сессии).
    // Только для БД — in-memory-хранилища живут не дольше процесса и сами
    // теряются при рестарте. Останавливается при закрытии сервера (onClose
    // ниже), до закрытия пула.
    const cleanup = new CleanupService(
      authCodeStore,
      emailSecretStore,
      sessionStore,
      ssoSessionStore,
      systemClock,
      [loginChallengeStore, googleNonceStore, pgOtpLimiter],
    );
    cleanupSchedule = startCleanupSchedule(
      async () => {
        const counts = await cleanup.runOnce();
        logger.info({ ...counts }, 'очистка устаревших данных');
      },
      3600 * 1000,
      (err) => logger.error({ err }, 'очистка устаревших данных не удалась'),
    );
  } else {
    identityRepo = new InMemoryIdentityRepository(systemClock);
    // Реестр клиентов из конфигурации (CLIENTS_JSON). Один экземпляр обслуживает
    // и LoginService (валидация /authorize), и HttpDeps.clients (роут /logout).
    clientRegistry = new InMemoryClientRegistry(config.clients);
    inMemoryCodeStore = new InMemoryAuthorizationCodeStore();
    authCodeStore = inMemoryCodeStore;
    const inMemoryRefreshTokens = new InMemoryRefreshTokenStore();
    sessionStore = new InMemorySessionStore(inMemoryRefreshTokens);
    refreshTokenStore = inMemoryRefreshTokens;
    ssoSessionStore = new InMemorySsoSessionStore();
    ssoStores = inMemorySsoStores(ssoSessionStore, sessionStore);
    emailSecretStore = new InMemoryEmailSecretStore();
    loginChallengeStore = new InMemoryLoginChallengeStore();
    googleNonceStore = new InMemoryGoogleNonceStore();
    otpRateLimiter = new InMemoryRateLimiter(systemClock);

    // Без БД ключ берётся из конфигурации (PEM) или автогенерируется.
    const key = await loadSigningKey({
      privateKeyPem: config.rsaPrivateKey,
      publicKeyPem: config.rsaPublicKey,
      kid: config.signingKeyKid,
      autogenerate: config.keyAutogenerate,
    });
    activeSigningKey = key;
    signingKeys = [key];
  }

  const tokenService = new TokenService(activeSigningKey, signingKeys, systemClock, {
    issuer: config.issuerUrl,
    accessTtlSeconds: config.accessTtlSeconds,
    idTtlSeconds: config.idTtlSeconds,
  });

  const identityService = new IdentityService(identityRepo);
  const authCodeService = new AuthorizationCodeService(authCodeStore, systemClock, 60);
  const loginService = new LoginService(clientRegistry, identityService, authCodeService);

  const sessionConfig = { refreshTtlSeconds: config.refreshTtlSeconds };
  const sessionService = new SessionService(
    sessionStore,
    refreshTokenStore,
    tokenService,
    systemClock,
    sessionConfig,
  );

  // Обмен кода и изменение клиента сериализуются блокировкой клиента. В БД
  // сервисы внутри неё работают через хранилища поверх той же транзакции.
  const clientLock: ClientLock = db
    ? new PgClientLock(db, (tx) => ({
        codes: new AuthorizationCodeService(new PgAuthorizationCodeStore(tx), systemClock, 60),
        sso: new PgSsoSessionStore(tx),
        sessions: new SessionService(new PgSessionStore(tx), new PgRefreshTokenStore(tx),
          tokenService, systemClock, sessionConfig),
      }))
    : new InMemoryClientLock(
        clientRegistry as ClientWriteStore,
        { codes: authCodeService, sessions: sessionService, sso: ssoSessionStore },
        (clientId) => inMemoryCodeStore!.invalidateForClient(clientId, systemClock.now()),
      );

  // Боевой путь — Resend (нужны ключ и адрес отправителя). Иначе LogMailer:
  // письма не отправляются, в журнал попадает только факт письма без кода.
  let mailer: Mailer;
  if (config.resendApiKey && config.emailFrom) {
    mailer = createResendMailer({
      apiKey: config.resendApiKey,
      fromEmail: config.emailFrom,
      fromName: config.emailFromName,
      logger,
    });
  } else {
    logger.warn(
      { resend: Boolean(config.resendApiKey), from: Boolean(config.emailFrom) },
      'почта не настроена — письма с кодами не отправляются',
    );
    mailer = new LogMailer(logger);
  }
  const codeProvider = new EmailCodeProvider(loginChallengeStore, mailer, systemClock, {
    appName: config.emailAppName,
    codeTtlMinutes: 15,
    ...(opts?.codeGenerator ? { generateCode: opts.codeGenerator } : {}),
  });

  // Google-вход собирается только при заданном GOOGLE_CLIENT_ID: без него
  // кнопки нет и маршрут отвечает ошибкой. Секрет клиента не нужен.
  const googleNonces = new GoogleNonceService(googleNonceStore, systemClock);
  const googleProvider = config.googleClientId
    ? new GoogleProvider(createGoogleTokenVerifier(config.googleClientId), googleNonces)
    : undefined;

  const ssoService = new SsoSessionService(ssoStores, systemClock, {
    ssoTtlSeconds: config.ssoTtlSeconds,
  });

  // Redis-лимитер разделяет состояние между инстансами; при отсутствии
  // REDIS_URL — in-memory (single-process).
  const rateLimiter = config.redisUrl
    ? createRedisRateLimiter(
        config.redisUrl,
        (err) => logger.warn({ err }, 'Redis-лимитер недоступен — считаем по лимитеру процесса'),
        new InMemoryRateLimiter(systemClock),
      )
    : new InMemoryRateLimiter(systemClock);

  const deps: HttpDeps = {
    config,
    logger,
    login: loginService,
    codes: authCodeService,
    sessions: sessionService,
    tokens: tokenService,
    signingKey: activeSigningKey,
    signingKeys,
    codeProvider,
    googleProvider,
    ...(googleProvider ? { googleNonces } : {}),
    identity: identityRepo,
    sso: ssoService,
    clients: clientRegistry,
    // И Pg-, и in-memory-реестры реализуют ClientWriteStore; переменная объявлена
    // как ClientRegistry, поэтому сужаем тип приведением.
    adminClients: clientRegistry as ClientWriteStore,
    clientLock,
    rateLimiter,
    otpRateLimiter,
  };

  const app = buildServer(deps);
  // app.close() (shutdownGracefully) дожидается идущей очистки до закрытия пула.
  if (cleanupSchedule) {
    const schedule = cleanupSchedule;
    app.addHook('onClose', async () => schedule.stop());
  }

  logger.info(
    { kid: activeSigningKey.kid, keys: signingKeys.length, issuer: config.issuerUrl },
    'auth-service ready',
  );
  return {
    config,
    logger,
    tokenService,
    signingKey: activeSigningKey,
    signingKeys,
    app,
    db,
    rateLimiter,
  };
}

// Аккуратное завершение: сначала перестаём принимать и дослуживаем текущие
// запросы (app.close), затем закрываем пул БД и соединение лимитера. Ошибки
// глотаем — при завершении важно дойти до конца, а не упасть на полпути.
export async function shutdownGracefully(
  app: Pick<FastifyInstance, 'close'>,
  db: Db | undefined,
  rateLimiter?: Pick<RateLimiter, 'close'>,
): Promise<void> {
  try {
    await app.close();
  } catch {
    // уже завершаемся
  }
  try {
    await db?.close();
  } catch {
    // уже завершаемся
  }
  try {
    await rateLimiter?.close();
  } catch {
    // уже завершаемся
  }
}

// Завершение с предохранителем: если graceful не уложился в timeoutMs
// (зависший запрос, мёртвое соединение с БД) — возвращаем 'timeout', чтобы
// вызывающий вышел сам, не дожидаясь SIGKILL. Никогда не reject'ит.
export async function shutdownWithTimeout(
  app: Pick<FastifyInstance, 'close'>,
  db: Db | undefined,
  timeoutMs: number,
  rateLimiter?: Pick<RateLimiter, 'close'>,
): Promise<'ok' | 'timeout'> {
  return Promise.race([
    shutdownGracefully(app, db, rateLimiter).then(() => 'ok' as const),
    new Promise<'timeout'>((resolve) => {
      // unref: таймер-предохранитель не должен сам удерживать процесс живым.
      setTimeout(() => resolve('timeout'), timeoutMs).unref();
    }),
  ]);
}

// pathToFileURL корректно кодирует путь (кириллица, пробелы) — ручная
// строка `file://${argv}` не совпала бы с percent-encoded import.meta.url.
const entry = process.argv[1];
const isMain = entry !== undefined && import.meta.url === pathToFileURL(entry).href;
if (isMain) {
  bootstrap()
    .then(async ({ config, app, db, logger, rateLimiter }) => {
      await app.listen({ port: config.port, host: '0.0.0.0' });
      for (const signal of ['SIGTERM', 'SIGINT'] as const) {
        // once: повторный сигнал во время завершения снимает обработчик и
        // убивает процесс немедленно — это намеренный аварийный выход.
        process.once(signal, () => {
          logger.info({ signal }, 'завершение по сигналу');
          // 8000 мс — запас под 10-секундный grace period docker stop.
          void shutdownWithTimeout(app, db, 8000, rateLimiter).then((result) => {
            if (result === 'timeout') {
              logger.error('graceful shutdown не уложился в таймаут — аварийный выход');
              process.exit(1);
            }
            process.exit(0);
          });
        });
      }
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
