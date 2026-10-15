import { OAuth2Client } from 'google-auth-library';
import type {
  GoogleTokenPayload,
  GoogleTokenVerifier,
} from '../../domain/google-login/google-provider.js';

// Боевая проверка ID Token через google-auth-library: подпись по ключам Google
// (кэшируются библиотекой), issuer, срок действия и audience = наш client id.
export function createGoogleTokenVerifier(clientId: string): GoogleTokenVerifier {
  const client = new OAuth2Client(clientId);
  return {
    async verify(idToken: string): Promise<GoogleTokenPayload> {
      const ticket = await client.verifyIdToken({ idToken, audience: clientId });
      const p = ticket.getPayload();
      if (!p?.sub) throw new Error('ID Token без payload/sub');
      return {
        sub: p.sub,
        email: p.email,
        emailVerified: p.email_verified === true,
        // hd — домен Workspace; без него сторонний адрес не считается
        // доказанно принадлежащим владельцу (см. isGoogleAuthoritativeEmail).
        hd: typeof p.hd === 'string' ? p.hd : undefined,
        name: p.name,
        avatarUrl: p.picture,
        // nonce библиотека кладёт в payload как есть, но не сверяет — сверку с
        // ожидаемым значением делает GoogleProvider (анти-replay).
        nonce: typeof p.nonce === 'string' ? p.nonce : undefined,
      };
    },
  };
}
