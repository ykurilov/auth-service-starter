import pino, { type DestinationStream, type Logger } from 'pino';

// Страховка на случай, если адаптер по ошибке передаст в журнал секрет или
// персональные данные: поля с этими именами (без учёта регистра) скрываются на
// любой глубине, в том числе в массивах. Основная защита — сами адаптеры пишут
// только безопасное (id письма у провайдера, тип письма, хеш адреса).
// Ошибки (на любой глубине) выводим только безопасными полями: тип,
// сообщение, код ошибки (pg, сеть — нужен для разбора сбоев), стек и так же
// отфильтрованная причина. Прикреплённые к ошибке данные (адрес, handle
// попытки, detail из pg с значениями строк, ответ провайдера) не выводятся.
// Код ошибки вне err пишем как errorCode: поле code скрывается, это может
// быть код из письма.
const SECRET_KEYS = new Set([
  'code', 'to', 'email', 'subject', 'text', 'html',
  'token', 'refreshtoken', 'refresh_token', 'refresh', 'accesstoken', 'access_token', 'id_token', 'idtoken',
  'credential', 'password', 'secret', 'client_secret', 'authorization', 'cookie', 'set-cookie',
  'state', 'nonce', 'code_verifier', 'codeverifier',
  'x-api-key', 'x-admin-token', 'adminapitoken', 'admin_api_token',
]);

const CENSOR = '[скрыто]';
const CYCLE = '[цикл]';
const TOO_DEEP = '[глубже не показано]';
const MAX_DEPTH = 8;

// Объект, встреченный повторно по другой ссылке, получает ту же скрытую копию
// (done); ссылка на предка — цикл. Глубже предела объект не выводится вовсе:
// вернуть его как есть значило бы показать его поля без скрытия.
function redactDeep(
  value: unknown,
  depth: number,
  ancestors: WeakSet<object>,
  done: WeakMap<object, unknown>,
): unknown {
  if (value === null || typeof value !== 'object' || value instanceof Date) return value;
  if (done.has(value)) return done.get(value);
  if (ancestors.has(value)) return CYCLE;
  if (depth >= MAX_DEPTH) return TOO_DEEP;
  ancestors.add(value);
  let out: unknown;
  if (value instanceof Error) {
    out = safeError(value, depth, ancestors, done);
  } else if (Array.isArray(value)) {
    out = value.map((item) => redactDeep(item, depth + 1, ancestors, done));
  } else {
    const fields: Record<string, unknown> = {};
    for (const [key, inner] of Object.entries(value)) {
      fields[key] = SECRET_KEYS.has(key.toLowerCase()) ? CENSOR : redactDeep(inner, depth + 1, ancestors, done);
    }
    out = fields;
  }
  ancestors.delete(value);
  done.set(value, out);
  return out;
}

function safeError(
  err: Error,
  depth: number,
  ancestors: WeakSet<object>,
  done: WeakMap<object, unknown>,
): Record<string, unknown> {
  const code: unknown = (err as { code?: unknown }).code;
  return {
    type: err.constructor?.name || err.name,
    message: err.message,
    ...(typeof code === 'string' || typeof code === 'number' ? { code } : {}),
    ...(err.stack !== undefined ? { stack: err.stack } : {}),
    ...(err.cause !== undefined ? { cause: redactDeep(err.cause, depth + 1, ancestors, done) } : {}),
  };
}

export function createLogger(level = 'info', destination?: DestinationStream): Logger {
  const options = {
    level,
    base: undefined,
    // Ошибку уже разобрал formatters.log (redactDeep): штатный сериализатор
    // pino принял бы её сводку за ошибку и вывел заново как Object.
    serializers: { err: (value: unknown) => value },
    formatters: { log: (object: Record<string, unknown>) => redactDeep(object, 0, new WeakSet(), new WeakMap()) as Record<string, unknown> },
  };
  return destination ? pino(options, destination) : pino(options);
}

export type { Logger };
