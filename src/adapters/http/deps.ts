import type { Logger } from 'pino';
import type { Config } from '../../config/config.js';
import type { LoginService } from '../../domain/login/login-service.js';
import type { AuthorizationCodeService } from '../../domain/login/authorization-code-service.js';
import type { SessionService } from '../../domain/sessions/session-service.js';
import type { TokenService } from '../../domain/tokens/token-service.js';
import type { SigningKey } from '../../domain/tokens/signing-key.js';
import type { EmailCodeProvider } from '../../domain/email-login/email-code-provider.js';
import type { IdentityRepository } from '../../domain/identity/identity-repository.js';
import type { IdentityProvider } from '../../domain/identity/provider-identity.js';
import type { SsoSessionService } from '../../domain/sso/sso-session-service.js';
import type { ClientRegistry, ClientWriteStore } from '../../domain/clients/client.js';
import type { RateLimiter } from '../../ports/rate-limiter.js';
import type { GoogleNonceService } from '../../domain/google-login/google-nonce.js';

export interface HttpDeps {
  config: Config;
  logger: Logger;
  login: LoginService;
  codes: AuthorizationCodeService;
  sessions: SessionService;
  tokens: TokenService;
  signingKey: SigningKey;
  signingKeys: SigningKey[];
  codeProvider: EmailCodeProvider;
  // Вход через Google. Отсутствует, когда GOOGLE_CLIENT_ID не задан: кнопка
  // не рендерится, POST /authorize/google отвечает ошибкой.
  googleProvider?: IdentityProvider;
  // Серверные одноразовые nonce для кнопки Google. Есть вместе с googleProvider.
  googleNonces?: GoogleNonceService;
  identity: IdentityRepository;
  sso: SsoSessionService;
  clients: ClientRegistry;
  // Записываемый реестр для Admin API. Опционален: без него роут /admin/clients
  // не монтируется.
  adminClients?: ClientWriteStore;
  rateLimiter: RateLimiter;
  // Лимитер кодов из письма (отправка и проверка). В боевом режиме — Postgres:
  // общий для экземпляров, переживает перезапуск и не зависит от Redis.
  otpRateLimiter: RateLimiter;
}
