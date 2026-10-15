import type { Client } from '../clients/client.js';
import type { AuthorizationGrant } from './authorization-code.js';

// Код обменивается только по тем правилам клиента, по которым выдан: клиент
// есть, провайдер входа разрешён, адрес возврата зарегистрирован, а тип клиента
// тот же, по которому вход решал, нужно ли согласие. Сверять под блокировкой
// клиента (ClientLock.shared), иначе PATCH может проскочить между проверкой и
// созданием сессии.
export function grantFitsClient(
  client: Client | null,
  grant: AuthorizationGrant,
  redirectUri: string,
): client is Client {
  return (
    client !== null &&
    client.type === grant.clientType &&
    client.allowedProviders.includes(grant.auth.provider) &&
    client.redirectUris.includes(redirectUri)
  );
}
