import type { Client, ClientType } from './client.js';

export interface DeriveClientInput {
  baseUrl: string;
  type?: ClientType;
  allowedProviders?: string[];
}

// Конвенция интеграции: приложению достаточно назвать свой адрес — технические
// адреса возврата сервис выводит сам. Это убирает главный класс ошибок агентов
// (руками составленные redirect_uri). Callback-путь фиксирован и должен
// совпадать с путём в клиентском мини-модуле: /api/auth/callback.
export const CALLBACK_PATH = '/api/auth/callback';

export function deriveClientFromBaseUrl(input: DeriveClientInput): Client {
  const origin = new URL(input.baseUrl).origin;
  // По умолчанию приложение считаем внутренним (наш собственный сервис):
  // internal-клиенту доступен вход через Google. Сторонний интегратор
  // указывает type='external' явно — для него Google выключен политикой сервиса.
  const type = input.type ?? 'internal';
  // Провайдеры по умолчанию зависят от типа: internal получает почту и Google
  // сразу, external — только почту. Чтобы отключить Google у internal, клиент
  // передаёт allowedProviders явно (например ['email']).
  const allowedProviders =
    input.allowedProviders ?? (type === 'internal' ? ['email', 'google'] : ['email']);
  return {
    id: new URL(origin).hostname,
    type,
    redirectUris: [`${origin}${CALLBACK_PATH}`],
    allowedProviders,
    postLogoutRedirectUris: [`${origin}/`],
  };
}
