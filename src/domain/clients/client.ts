export type ClientType = 'internal' | 'external';

export interface Client {
  id: string;
  type: ClientType;
  redirectUris: string[]; // точный allowlist (exact match, без wildcard)
  allowedProviders: string[]; // ключи провайдеров: 'email' | 'google' | 'vk' | 'yandex'
  postLogoutRedirectUris?: string[]; // allowlist для post_logout_redirect_uri (SSO logout)
}

export interface ClientRegistry {
  findClient(id: string): Promise<Client | null>;
}

// Частичный патч клиента для Admin API. id менять нельзя.
export type ClientPatch = Partial<Omit<Client, 'id'>>;

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
