import pino, { type DestinationStream, type Logger } from 'pino';

// Страховка на случай, если адаптер по ошибке передаст в журнал секрет или
// персональные данные: поля с этими именами (без учёта регистра) скрываются на
// любой глубине, в том числе в массивах. Основная защита — сами адаптеры пишут
// только безопасное (id письма у провайдера, тип письма, хеш адреса).
// Объекты ошибок не обходим: их сериализует pino, а err.code — код ошибки
// (pg, сеть), он нужен для разбора сбоев. Код ошибки вне err пишем как
// errorCode: поле code скрывается, это может быть код из письма.
const SECRET_KEYS = new Set([
  'code', 'to', 'email', 'subject', 'text', 'html',
  'token', 'refreshtoken', 'refresh_token', 'refresh', 'accesstoken', 'access_token', 'id_token', 'idtoken',
  'credential', 'password', 'secret', 'client_secret', 'authorization', 'cookie', 'set-cookie',
  'state', 'nonce', 'code_verifier', 'codeverifier',
  'x-api-key', 'x-admin-token', 'adminapitoken', 'admin_api_token',
]);

const CENSOR = '[скрыто]';
const MAX_DEPTH = 8;

function redactDeep(value: unknown, depth: number, seen: WeakSet<object>): unknown {
  if (value === null || typeof value !== 'object' || value instanceof Error || value instanceof Date) return value;
  if (depth >= MAX_DEPTH || seen.has(value)) return value;
  seen.add(value);
  if (Array.isArray(value)) return value.map((item) => redactDeep(item, depth + 1, seen));
  const out: Record<string, unknown> = {};
  for (const [key, inner] of Object.entries(value)) {
    out[key] = SECRET_KEYS.has(key.toLowerCase()) ? CENSOR : redactDeep(inner, depth + 1, seen);
  }
  return out;
}

export function createLogger(level = 'info', destination?: DestinationStream): Logger {
  const options = {
    level,
    base: undefined,
    formatters: { log: (object: Record<string, unknown>) => redactDeep(object, 0, new WeakSet()) as Record<string, unknown> },
  };
  return destination ? pino(options, destination) : pino(options);
}

export type { Logger };
