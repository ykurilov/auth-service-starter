import type { ProviderIdentity } from '../identity/provider-identity.js';

// Единый провайдер 'email' для входа по коду: на уровне клиента это одно
// разрешение ('email' в allowedProviders) и один auth_provider в токене.
export const EMAIL_PROVIDER = 'email';

// Слот личности (provider, subject) входа по коду. Раньше рядом жил слот пароля
// ('password:<email>', emailVerified:false); пароль убран — вход по почте
// теперь только по коду, поэтому слот один.
function codeSubject(email: string): string {
  return `code:${email}`;
}

// Вход по коду: код пришёл на почту и введён -> владение доказано.
export function codeIdentity(email: string): ProviderIdentity {
  return {
    provider: EMAIL_PROVIDER,
    subject: codeSubject(email),
    email,
    emailVerified: true,
    profile: {},
  };
}
