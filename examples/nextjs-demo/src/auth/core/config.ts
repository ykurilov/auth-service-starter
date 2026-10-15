// Конфиг модуля из env. Всё проверяем при загрузке — с понятными русскими
// ошибками, чтобы агент при интеграции сразу видел, чего не хватает.
// fetch и env внедряемы: в тестах модуль ходит в сервис in-process через мост.
export interface ModuleConfig {
  authUrl: string; // origin сервиса, без хвостового слэша
  appUrl: string; // origin приложения
  clientId: string;
  cookieSecret: string;
  fetch: typeof fetch;
  timeoutMs?: number;
}

export interface LoadConfigOptions {
  env?: Record<string, string | undefined>;
  fetch?: typeof fetch;
  /** Общий deadline fetch + чтение тела; по умолчанию 10 секунд. */
  timeoutMs?: number;
}

function requireOrigin(value: string | undefined, name: string): string {
  if (!value || value.trim() === '') {
    throw new Error(`Не задана переменная окружения ${name}`);
  }
  try {
    const url = new URL(value);
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if (url.username || url.password || url.search || url.hash ||
        (url.protocol !== 'https:' && !(url.protocol === 'http:' && local))) throw new Error('unsafe origin');
    return url.origin;
  } catch {
    throw new Error(`${name} должна быть HTTPS URL без credentials, query и fragment (HTTP разрешён для localhost)`);
  }
}

// process.env читаем через globalThis, не импортируя node:process — core
// остаётся на чистых Web-стандартах, а в среде без process (браузер) просто
// сработает обычная проверка «переменная не задана».
type MaybeNodeGlobal = { process?: { env?: Record<string, string | undefined> } };

function envOf(options: LoadConfigOptions): Record<string, string | undefined> {
  return options.env ?? (globalThis as MaybeNodeGlobal).process?.env ?? {};
}

// Адрес приложения и client_id — всё, от чего зависят имена cookie. Секрет
// для этого не нужен: так метку тихой проверки можно прочитать без него.
export function loadAppIdentity(options: LoadConfigOptions = {}): Pick<ModuleConfig, 'appUrl' | 'clientId'> {
  const env = envOf(options);
  const appUrl = requireOrigin(env.AUTH_APP_URL, 'AUTH_APP_URL');
  // client_id по умолчанию = hostname адреса приложения (та же конвенция, что у
  // краткой регистрации { baseUrl } в Admin API сервиса).
  const clientId =
    env.AUTH_CLIENT_ID && env.AUTH_CLIENT_ID.trim() !== ''
      ? env.AUTH_CLIENT_ID
      : new URL(appUrl).hostname;
  return { appUrl, clientId };
}

export function loadModuleConfig(options: LoadConfigOptions = {}): ModuleConfig {
  const env = envOf(options);
  const authUrl = requireOrigin(env.AUTH_URL, 'AUTH_URL');
  const { appUrl, clientId } = loadAppIdentity(options);

  const secret = env.AUTH_COOKIE_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('AUTH_COOKIE_SECRET должна содержать не менее 32 символов');
  }

  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new Error('fetch недоступен: передайте fetch в конфиг или используйте среду с глобальным fetch');
  }

  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('timeoutMs должен быть положительным');
  return { authUrl, appUrl, clientId, cookieSecret: secret, fetch: fetchImpl, timeoutMs };
}
