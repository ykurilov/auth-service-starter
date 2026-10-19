import { z } from 'zod';
import { isIP } from 'node:net';
import type { Client } from '../domain/clients/client.js';
import {
  assertProvidersAllowedForType,
  clientCreateSchema,
} from '../domain/clients/client-validation.js';

// CLIENTS_JSON: пусто/нет -> []; иначе JSON.parse (свой текст ошибки при провале)
// + та же доменная проверка, что и Admin API (clientCreateSchema): redirect_uri
// только https/localhost, провайдеры из KNOWN_PROVIDERS, google не для external.
// Единый валидатор на оба пути регистрации клиента — иначе клиент из .env мог бы
// получить http-redirect или неизвестный провайдер в обход правил Admin API.
function parseClients(raw: string | undefined): Client[] {
  if (!raw || raw.trim() === '') return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('CLIENTS_JSON: невалидный JSON реестра клиентов');
  }
  const clients = z.array(clientCreateSchema).parse(parsed);
  for (const c of clients) assertProvidersAllowedForType(c.type, c.allowedProviders);
  return clients.map((c) => ({
    id: c.id,
    type: c.type,
    redirectUris: c.redirectUris,
    allowedProviders: c.allowedProviders,
    ...(c.postLogoutRedirectUris !== undefined
      ? { postLogoutRedirectUris: c.postLogoutRedirectUris }
      : {}),
  }));
}

const pem = z
  .string()
  .optional()
  .transform((v) => (v ? v.replace(/\\n/g, '\n') : v));

const schema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(3016),
  TOKEN_RATE_LIMIT: z.coerce.number().int().positive().default(10000),
  // Писем с кодом с одного IP за час (новые попытки и переотправки на все
  // адреса). Класс или офис за одним адресом делят этот бюджет.
  CODE_REQUEST_PER_IP_HOURLY: z.coerce.number().int().positive().default(100),
  // Неверных кодов с одного IP за час на все попытки и адреса. Верный код
  // бюджет не тратит. По умолчанию равен CODE_REQUEST_PER_IP_HOURLY: группа,
  // которой хватает писем, не упрётся и в проверки.
  CODE_VERIFY_PER_IP_HOURLY: z.coerce.number().int().positive().optional(),
  // Входов через Google с одного IP за 15 минут.
  GOOGLE_SIGNIN_PER_IP_15MIN: z.coerce.number().int().positive().default(60),
  // Хвостовой слэш срезаем: адреса discovery строятся конкатенацией
  // `${issuer}/authorize`, и слэш в .env дал бы двойной слэш во всех путях.
  PUBLIC_ISSUER_URL: z
    .string()
    .url()
    .refine((v) => {
      const url = new URL(v);
      const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
      return !url.username && !url.password && !url.search && !url.hash && /^\/*$/.test(url.pathname) &&
        (url.protocol === 'https:' || (url.protocol === 'http:' && local));
    }, 'PUBLIC_ISSUER_URL: укажите HTTPS origin без пути (HTTP только localhost)')
    .transform((v) => new URL(v).origin),
  RSA_PRIVATE_KEY: pem,
  RSA_PUBLIC_KEY: pem,
  SIGNING_KEY_KID: z.string().optional(),
  KEY_AUTOGENERATE: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),
  ACCESS_TTL_SECONDS: z.coerce.number().int().positive().default(900),
  ID_TTL_SECONDS: z.coerce.number().int().positive().default(900),
  REFRESH_TTL_SECONDS: z.coerce.number().int().positive().default(2592000),
  CLIENTS_JSON: z.string().optional(),
  DATABASE_URL: z.string().optional(),
  REDIS_URL: z.string().optional(),
  MIGRATE_ON_BOOT: z
    .enum(['true', 'false'])
    .default('true')
    .transform((v) => v === 'true'),
  SSO_TTL_SECONDS: z.coerce.number().int().positive().default(2592000),
  SSO_COOKIE_NAME: z.string().default('sso'),
  CSRF_COOKIE_NAME: z.string().default('csrf'),
  SSO_COOKIE_SECURE: z
    .enum(['true', 'false'])
    .default('true')
    .transform((v) => v === 'true'),
  // Список IP/CIDR доверенных прокси, например loopback,172.30.240.1.
  // Старые true/N оставлены только для loopback; публичному адресу не доверяем.
  TRUST_PROXY: z.string().default('false').transform((v, ctx) => {
    const t = v.trim().toLowerCase();
    if (!t || t === 'false') return 0;
    if (t === 'true') return 1;
    if (/^\d+$/.test(t) && Number.isSafeInteger(Number(t)) && Number(t) <= 16) return Number(t);
    const addresses = t.split(',').map((x) => x.trim());
    const valid = addresses.every((address) => {
      if (['loopback', 'linklocal', 'uniquelocal'].includes(address)) return true;
      const [ip, bits, extra] = address.split('/');
      const family = isIP(ip!);
      return !extra && family !== 0 && (bits === undefined || (/^\d+$/.test(bits) && Number(bits) <= (family === 4 ? 32 : 128)));
    });
    if (!valid) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'TRUST_PROXY: укажите IP/CIDR доверенных прокси, loopback или false' });
      return z.NEVER;
    }
    return addresses;
  }),
  LOG_LEVEL: z.string().default('info'),
  EMAIL_APP_NAME: z.string().default('Auth Service'),
  RESEND_API_KEY: z
    .string()
    .optional()
    .transform((v) => (v ? v.trim() : v)),
  EMAIL_FROM: z.string().optional(),
  EMAIL_FROM_NAME: z.string().optional(),
  // OAuth client id Google (Google Identity Services). Пусто/нет → вход через
  // Google выключен: кнопка не рендерится, маршрут отвечает ошибкой.
  // Секрет клиента не нужен вовсе: фронт получает ID Token, бэк проверяет подпись.
  GOOGLE_CLIENT_ID: z
    .string()
    .optional()
    .transform((v) => {
      const t = v?.trim();
      return t ? t : undefined;
    }),
  // Bearer-токен Admin API реестра клиентов. Пусто/нет → Admin API не монтируется.
  ADMIN_API_TOKEN: z
    .string()
    .optional()
    .transform((v) => {
      const t = v?.trim();
      return t ? t : undefined;
    }),
});

export interface RateLimitRule {
  limit: number;
  windowSeconds: number;
}

export interface RateLimits {
  identifyPerIp: RateLimitRule;
  googleNoncePerIp: RateLimitRule;
  codeRequest: RateLimitRule;
  codeRequestPerIp: RateLimitRule;
  codeRequestEmailPause: RateLimitRule;
  codeRequestPerEmailDaily: RateLimitRule;
  codeVerifyPerIp: RateLimitRule;
  token: RateLimitRule;
  revoke: RateLimitRule;
}

export interface Config {
  port: number;
  issuerUrl: string;
  rsaPrivateKey?: string;
  rsaPublicKey?: string;
  signingKeyKid?: string;
  keyAutogenerate: boolean;
  accessTtlSeconds: number;
  idTtlSeconds: number;
  refreshTtlSeconds: number;
  clients: Client[];
  databaseUrl?: string;
  redisUrl?: string;
  migrateOnBoot: boolean;
  ssoTtlSeconds: number;
  ssoCookieName: string;
  csrfCookieName: string;
  ssoCookieSecure: boolean;
  trustProxy: number | string[];
  logLevel: string;
  emailAppName: string;
  resendApiKey?: string;
  emailFrom?: string;
  emailFromName?: string;
  adminApiToken?: string;
  googleClientId?: string;
  rateLimits: RateLimits;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const p = schema.parse(env);
  return {
    port: p.PORT,
    issuerUrl: p.PUBLIC_ISSUER_URL,
    rsaPrivateKey: p.RSA_PRIVATE_KEY,
    rsaPublicKey: p.RSA_PUBLIC_KEY,
    signingKeyKid: p.SIGNING_KEY_KID,
    keyAutogenerate: p.KEY_AUTOGENERATE,
    accessTtlSeconds: p.ACCESS_TTL_SECONDS,
    idTtlSeconds: p.ID_TTL_SECONDS,
    refreshTtlSeconds: p.REFRESH_TTL_SECONDS,
    clients: parseClients(p.CLIENTS_JSON),
    databaseUrl: p.DATABASE_URL,
    redisUrl: p.REDIS_URL,
    migrateOnBoot: p.MIGRATE_ON_BOOT,
    ssoTtlSeconds: p.SSO_TTL_SECONDS,
    ssoCookieName: p.SSO_COOKIE_NAME,
    csrfCookieName: p.CSRF_COOKIE_NAME,
    ssoCookieSecure: p.SSO_COOKIE_SECURE,
    trustProxy: p.TRUST_PROXY,
    logLevel: p.LOG_LEVEL,
    emailAppName: p.EMAIL_APP_NAME,
    resendApiKey: p.RESEND_API_KEY,
    emailFrom: p.EMAIL_FROM,
    emailFromName: p.EMAIL_FROM_NAME,
    adminApiToken: p.ADMIN_API_TOKEN,
    googleClientId: p.GOOGLE_CLIENT_ID,
    rateLimits: {
      // Лимит POST /authorize/google по IP: просторный для общих IP (офис, кафе).
      identifyPerIp: { limit: p.GOOGLE_SIGNIN_PER_IP_15MIN, windowSeconds: 900 },
      // Выпуск Google nonce при показе страницы входа (в т.ч. страниц ошибок):
      // отдельный счётчик, чтобы просмотры страниц не тратили бюджет входа.
      googleNoncePerIp: { limit: 300, windowSeconds: 900 },
      // Отправка кода (счётчики в Postgres, общие для экземпляров).
      // По ip — общий бюджет писем одного источника на все адреса: новые
      // попытки и переотправки (настраивается CODE_REQUEST_PER_IP_HOURLY).
      // Остальные три считают только НОВЫЕ попытки входа: переотправка в живой
      // попытке ограничена самой попыткой (3 раза).
      // По (ip+email) — против одного источника. По email — бюджет адреса
      // против ротации IP: пауза 60 с между новыми письмами и суточный потолок.
      // Посторонний, знающий адрес, может занять этот бюджет: владелец тогда
      // ждёт паузу (секунды), а при исчерпанном потолке — до конца суток. Уже
      // начатый вход владельца это не задевает: переотправка бюджет адреса не
      // тратит. Это осознанная цена защиты ящика от бомбинга (docs/DEPLOY.md).
      // Каждая попытка — не больше 4 писем и 5 проверок: на один адрес за сутки
      // не больше 20×4 писем и 20×5 догадок.
      codeRequest: { limit: 5, windowSeconds: 900 },
      codeRequestPerIp: { limit: p.CODE_REQUEST_PER_IP_HOURLY, windowSeconds: 3600 },
      codeRequestEmailPause: { limit: 1, windowSeconds: 60 },
      codeRequestPerEmailDaily: { limit: 20, windowSeconds: 86400 },
      // Проверка кода: общий бюджет неверных кодов одного IP на все попытки и
      // адреса (верный код списание возвращает). Лимит по адресу намеренно не
      // вводим: им посторонний заблокировал бы владельца — у каждой попытки
      // свой лимит проверок (5) в самой записи.
      codeVerifyPerIp: {
        limit: p.CODE_VERIFY_PER_IP_HOURLY ?? p.CODE_REQUEST_PER_IP_HOURLY,
        windowSeconds: 3600,
      },
      token: { limit: p.TOKEN_RATE_LIMIT, windowSeconds: 900 },
      revoke: { limit: 60, windowSeconds: 900 },
    },
  };
}
