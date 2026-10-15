import type { Client, ClientRegistry } from '../clients/client.js';
import type { IdentityService } from '../identity/identity-service.js';
import type { ProviderIdentity } from '../identity/provider-identity.js';
import type { AuthorizationCodeService } from './authorization-code-service.js';
import type { AuthSnapshot } from './authorization-code.js';
import {
  InvalidClientError,
  InvalidRedirectUriError,
  ProviderNotAllowedError,
  UnsupportedPkceError,
} from './errors.js';

export interface AuthorizationRequest {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string; // ожидаем 'S256'
  scope: string;
  state?: string;
  nonce?: string;
}

export interface ValidatedAuthorization {
  client: Client;
  request: AuthorizationRequest;
}

export interface CompletedLogin {
  code: string;
  userId: string;
  auth: AuthSnapshot;
}

export class LoginService {
  constructor(
    private readonly clients: ClientRegistry,
    private readonly identity: IdentityService,
    private readonly codes: AuthorizationCodeService,
  ) {}

  // Проверка до страницы входа. Ошибки клиента/redirect нельзя редиректить обратно — бросаем.
  async validateRequest(req: AuthorizationRequest): Promise<ValidatedAuthorization> {
    const client = await this.clients.findClient(req.clientId);
    if (!client) throw new InvalidClientError();
    if (!client.redirectUris.includes(req.redirectUri)) {
      throw new InvalidRedirectUriError();
    }
    if (req.codeChallengeMethod !== 'S256' || !req.codeChallenge) {
      throw new UnsupportedPkceError();
    }
    return { client, request: req };
  }

  // После успешной аутентификации провайдером: связываем личность и выпускаем authorization code.
  async completeLogin(
    validated: ValidatedAuthorization,
    providerIdentity: ProviderIdentity,
  ): Promise<CompletedLogin> {
    if (!validated.client.allowedProviders.includes(providerIdentity.provider)) {
      throw new ProviderNotAllowedError(providerIdentity.provider);
    }
    const { user } = await this.identity.resolveLogin(providerIdentity);
    const auth: AuthSnapshot = {
      provider: providerIdentity.provider,
      email: providerIdentity.email,
      emailVerified: providerIdentity.emailVerified,
      name: providerIdentity.profile.name,
    };
    const code = await this.codes.issue({
      clientId: validated.client.id,
      userId: user.id,
      redirectUri: validated.request.redirectUri,
      codeChallenge: validated.request.codeChallenge,
      scope: validated.request.scope,
      nonce: validated.request.nonce,
      auth,
    });
    return { code, userId: user.id, auth };
  }

  // SSO: пользователь уже аутентифицирован (живая SSO-сессия), личность известна.
  // Не резолвим провайдера заново — выпускаем код по готовому снимку auth.
  async completeSsoLogin(
    validated: ValidatedAuthorization,
    userId: string,
    auth: AuthSnapshot,
  ): Promise<string> {
    if (!validated.client.allowedProviders.includes(auth.provider)) {
      throw new ProviderNotAllowedError(auth.provider);
    }
    return this.codes.issue({
      clientId: validated.client.id,
      userId,
      redirectUri: validated.request.redirectUri,
      codeChallenge: validated.request.codeChallenge,
      scope: validated.request.scope,
      nonce: validated.request.nonce,
      auth,
    });
  }
}
