import { z } from 'zod';
import type { IdentityProvider, ProviderIdentity } from '../identity/provider-identity.js';
import { parseEmailAddress } from '../identity/user.js';
import { InvalidCredentialsError } from '../email-login/errors.js';
import type { GoogleNonceService } from './google-nonce.js';

// Ключ провайдера — из KNOWN_PROVIDERS; клиентам без него Google-вход запрещён
// (completeLogin проверяет allowedProviders).
export const GOOGLE_PROVIDER = 'google';

// Полезная нагрузка уже проверенного ID Token: подпись, issuer, audience и срок
// действия проверяет реализация GoogleTokenVerifier (google-auth-library).
// nonce и hd извлекаются как есть; сверку nonce делает провайдер.
export interface GoogleTokenPayload {
  sub: string;
  email?: string;
  emailVerified: boolean;
  // Домен Google Workspace аккаунта (claim hd). Есть только у аккаунтов
  // организаций, где Google — авторитетный источник адресов этого домена.
  hd?: string;
  name?: string;
  avatarUrl?: string;
  nonce?: string;
}

export interface GoogleTokenVerifier {
  verify(idToken: string): Promise<GoogleTokenPayload>;
}

// Доказывает ли Google текущее владение адресом. По документации Google
// (verify-google-id-token) email_verified сам по себе этого не гарантирует для
// сторонних адресов: только @gmail.com или аккаунт Workspace (hd), чей домен
// совпадает с доменом адреса. Остальные адреса Google лишь когда-то проверил.
export function isGoogleAuthoritativeEmail(email: string, hd: string | undefined): boolean {
  const domain = email.slice(email.lastIndexOf('@') + 1).toLowerCase();
  if (domain === 'gmail.com') return true;
  return typeof hd === 'string' && hd.length > 0 && hd.toLowerCase() === domain;
}

// binding — значение csrf-cookie браузера, clientId — клиент OIDC-запроса:
// nonce выпускался ровно этой паре и гасится только ею.
const credentialSchema = z.object({
  credential: z.string().min(1),
  binding: z.string().min(1),
  clientId: z.string().min(1),
});

export class GoogleProvider implements IdentityProvider {
  readonly id = GOOGLE_PROVIDER;

  constructor(
    private readonly verifier: GoogleTokenVerifier,
    private readonly nonces: GoogleNonceService,
  ) {}

  // emailVerified в результате = владение адресом доказано (см.
  // isGoogleAuthoritativeEmail). Сторонний адрес возвращается с
  // emailVerified:false: IdentityService не создаст и не привяжет по нему
  // пользователя, пока владелец не подтвердит адрес кодом из письма.
  async verify(credential: unknown): Promise<ProviderIdentity> {
    const { credential: idToken, binding, clientId } = credentialSchema.parse(credential);
    let payload: GoogleTokenPayload;
    try {
      payload = await this.verifier.verify(idToken);
    } catch {
      throw new InvalidCredentialsError();
    }
    // Одноразовость: nonce гасится атомарно на сервере. Без nonce, с чужим,
    // просроченным или уже погашенным — отказ (replay).
    if (!payload.nonce || !(await this.nonces.consume(payload.nonce, binding, clientId))) {
      throw new InvalidCredentialsError();
    }
    // Без адреса или с неподтверждённым Google адресом не принимаем вовсе.
    const email = payload.email ? parseEmailAddress(payload.email) : null;
    if (!email || !payload.emailVerified) throw new InvalidCredentialsError();
    return {
      provider: GOOGLE_PROVIDER,
      subject: payload.sub,
      email,
      emailVerified: isGoogleAuthoritativeEmail(email, payload.hd),
      profile: { name: payload.name, avatarUrl: payload.avatarUrl },
    };
  }
}
