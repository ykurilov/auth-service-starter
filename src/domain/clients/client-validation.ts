import { z } from 'zod';
import { KNOWN_PROVIDERS, type ClientType } from './client.js';

// Доменное правило нарушено (тип клиента несовместим с набором провайдеров).
// Отделено от zod-ошибок формата, чтобы роут мог различать причины 400.
export class ClientValidationError extends Error {}

// Внешним (external) клиентам нельзя выдавать google-вход: этот провайдер
// зарезервирован за внутренними приложениями.
export function assertProvidersAllowedForType(
  type: ClientType,
  providers: string[],
): void {
  if (type === 'external' && providers.includes('google')) {
    throw new ClientValidationError('external clients may not use google');
  }
}

// Адреса возврата принимаем только по https; http — лишь для локальной
// разработки (localhost/127.0.0.1). Иначе код авторизации мог бы уйти по
// нешифрованному каналу или на подставной хост.
export function isAllowedRedirectUri(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol === 'https:') return true;
  if (url.protocol === 'http:') {
    return url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  }
  return false;
}

const secureUri = z
  .string()
  .url()
  .refine(isAllowedRedirectUri, { message: 'uri must be https (http only for localhost)' });

// Формат тела POST /admin/clients: строгая проверка URL и известных провайдеров.
export const clientCreateSchema = z.object({
  id: z.string().min(1),
  type: z.enum(['internal', 'external']),
  redirectUris: z.array(secureUri).min(1),
  allowedProviders: z.array(z.enum(KNOWN_PROVIDERS)).min(1),
  postLogoutRedirectUris: z.array(secureUri).optional(),
});

// Краткая форма POST /admin/clients: приложение называет только свой адрес,
// остальные адреса возврата сервис выводит сам (см. deriveClientFromBaseUrl).
export const clientCreateByBaseUrlSchema = z.object({
  baseUrl: secureUri,
  type: z.enum(['internal', 'external']).optional(),
  allowedProviders: z.array(z.enum(KNOWN_PROVIDERS)).min(1).optional(),
});

// Формат тела PATCH /admin/clients/:id: те же поля, все опциональные, без id.
export const clientPatchSchema = z.object({
  type: z.enum(['internal', 'external']).optional(),
  redirectUris: z.array(secureUri).min(1).optional(),
  allowedProviders: z.array(z.enum(KNOWN_PROVIDERS)).min(1).optional(),
  postLogoutRedirectUris: z.array(secureUri).optional(),
});
