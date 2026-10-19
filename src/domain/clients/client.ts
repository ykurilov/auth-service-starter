export type ClientType = 'internal' | 'external';

export interface Client {
  id: string;
  type: ClientType;
  redirectUris: string[]; // точный allowlist (exact match, без wildcard)
  allowedProviders: string[]; // ключи провайдеров: 'email' | 'google' | 'vk' | 'yandex'
  postLogoutRedirectUris?: string[]; // allowlist для post_logout_redirect_uri (SSO logout)
  // Регистрация клиента: новое значение при каждом создании, PATCH его не
  // меняет. Клиент, удалённый и созданный заново с тем же id, — другая
  // регистрация. Задаётся хранилищем, наружу (Admin API) не отдаётся.
  registrationId?: string;
}

export interface ClientRegistry {
  findClient(id: string): Promise<Client | null>;
}

// Частичный патч клиента для Admin API. id и регистрацию менять нельзя.
export type ClientPatch = Partial<Omit<Client, 'id' | 'registrationId'>>;

// Клиент в ответах Admin API: без внутреннего идентификатора регистрации.
export function publicClient(client: Client): Client {
  const { registrationId: _registrationId, ...rest } = client;
  return rest;
}

// Клиент после патча: заданные поля заменяются, остальные остаются прежними.
export function applyClientPatch(client: Client, patch: ClientPatch): Client {
  const next: Client = {
    ...client,
    ...(patch.type !== undefined ? { type: patch.type } : {}),
    ...(patch.redirectUris !== undefined ? { redirectUris: patch.redirectUris } : {}),
    ...(patch.allowedProviders !== undefined ? { allowedProviders: patch.allowedProviders } : {}),
  };
  if (patch.postLogoutRedirectUris !== undefined) {
    next.postLogoutRedirectUris = patch.postLogoutRedirectUris;
  }
  return next;
}

// Записываемый порт реестра: чтение (findClient) + CRUD для Admin API.
// Реализуют и in-memory, и Postgres-реестры.
export interface ClientWriteStore extends ClientRegistry {
  list(): Promise<Client[]>;
  create(client: Client): Promise<void>;
  update(id: string, patch: ClientPatch): Promise<void>;
  delete(id: string): Promise<void>;
}

// Известные ключи провайдеров входа.
export const KNOWN_PROVIDERS = ['email', 'google', 'vk', 'yandex'] as const;
