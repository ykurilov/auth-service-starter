import { randomUUID } from 'node:crypto';
import type { Client, ClientRegistry } from '../clients/client.js';
import type { IdentityService } from '../identity/identity-service.js';
import type { ProviderIdentity } from '../identity/provider-identity.js';
import type { AuthorizationCodeService } from './authorization-code-service.js';
import type { AuthSnapshot } from './authorization-code.js';
import type { SsoSession } from '../sso/sso-session.js';
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

export interface AuthenticatedLogin {
  userId: string;
  auth: AuthSnapshot;
}

export interface CompletedLogin extends AuthenticatedLogin {
  code: string;
}

const CODE_CHALLENGE_FORMAT = /^[A-Za-z0-9_-]{43,128}$/;

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
    // RFC 7636 §4.2: challenge — 43–128 символов base64url (S256 даёт ровно 43).
    if (req.codeChallengeMethod !== 'S256' || !CODE_CHALLENGE_FORMAT.test(req.codeChallenge)) {
      throw new UnsupportedPkceError();
    }
    return { client, request: req };
  }

  // После успешной аутентификации провайдером: связываем личность и выпускаем authorization code.
  async completeLogin(
    validated: ValidatedAuthorization,
    providerIdentity: ProviderIdentity,
  ): Promise<CompletedLogin> {
    const { userId, auth } = await this.authenticate(validated, providerIdentity);
    const code = await this.codes.issue({
      clientId: validated.client.id,
      // Тип, по которому решено, нужно ли согласие, и регистрация из того же
      // снимка: обмен сверит их с текущими.
      clientType: validated.client.type,
      clientRegistrationId: validated.client.registrationId,
      userId,
      redirectUri: validated.request.redirectUri,
      codeChallenge: validated.request.codeChallenge,
      scope: validated.request.scope,
      nonce: validated.request.nonce,
      auth,
    });
    return { code, userId, auth };
  }

  // Аутентификация без выпуска кода: связываем личность и собираем снимок
  // входа. Внешнему приложению код выдаётся только после экрана согласия —
  // по SSO-сессии, начатой этим входом (completeSsoLogin).
  async authenticate(
    validated: ValidatedAuthorization,
    providerIdentity: ProviderIdentity,
  ): Promise<AuthenticatedLogin> {
    if (!validated.client.allowedProviders.includes(providerIdentity.provider)) {
      throw new ProviderNotAllowedError(providerIdentity.provider);
    }
    // Адрес и его статус — по базе после привязки, а не по ответу провайдера.
    const { user, email, emailVerified } = await this.identity.resolveLogin(providerIdentity);
    const auth: AuthSnapshot = {
      provider: providerIdentity.provider,
      email,
      emailVerified,
      // Имя — из базы, как в /userinfo, а не из ответа провайдера.
      name: user.displayName,
      loginId: randomUUID(),
    };
    return { userId: user.id, auth };
  }

  // SSO: пользователь уже аутентифицирован (живая SSO-сессия), личность известна.
  // Не резолвим провайдера заново — выпускаем код по готовому снимку auth.
  // Код помнит цепочку SSO-сессии: обмен сверит, что браузер не сменил в ней
  // аккаунт, даже если снимок auth без loginId (сессия до миграции 0013).
  async completeSsoLogin(
    validated: ValidatedAuthorization,
    session: Pick<SsoSession, 'userId' | 'auth' | 'chainId'>,
  ): Promise<string> {
    const { userId, auth } = session;
    if (!validated.client.allowedProviders.includes(auth.provider)) {
      throw new ProviderNotAllowedError(auth.provider);
    }
    return this.codes.issue({
      clientId: validated.client.id,
      // Тип, по которому решено, нужно ли согласие, и регистрация из того же
      // снимка: обмен сверит их с текущими.
      clientType: validated.client.type,
      clientRegistrationId: validated.client.registrationId,
      userId,
      redirectUri: validated.request.redirectUri,
      codeChallenge: validated.request.codeChallenge,
      scope: validated.request.scope,
      nonce: validated.request.nonce,
      auth,
      ssoChainId: session.chainId,
    });
  }
}
