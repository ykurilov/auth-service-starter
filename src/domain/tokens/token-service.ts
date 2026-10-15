import { SignJWT, jwtVerify } from 'jose';
import type { Clock } from '../../ports/clock.js';
import type { SigningKey } from './signing-key.js';
import type { AccessTokenClaims } from './claims.js';
import { normalizeScope, profileForScope } from './scope.js';

export interface TokenServiceConfig {
  issuer: string;
  accessTtlSeconds: number;
  idTtlSeconds: number;
}

export interface IssueTokenInput {
  userId: string;
  clientId: string;
  provider: string;
  roles: string[];
  profile: { email?: string; emailVerified?: boolean; name?: string };
  // Запрошенный и одобренный scope. Определяет, какие profile-claims попадут
  // в id_token (profile→name, email→email/email_verified) и кладётся в
  // access-token как claim `scope`, чтобы /userinfo мог отфильтровать ответ.
  scope: string;
  // OIDC Core: nonce из authorization request обязан вернуться в id_token,
  // иначе клиент не может защититься от подмены токена. Передаётся только
  // при первичной выдаче по коду; при refresh-ротации отсутствует.
  nonce?: string;
}

export interface IssuedCoreTokens {
  accessToken: string;
  idToken: string;
  expiresIn: number;
  // Нормализованный scope, реально выданный (может отличаться от запрошенного,
  // если клиент прислал неизвестные значения). OAuth 2.0 §5.1.
  scope: string;
}

export class TokenService {
  constructor(
    private readonly activeKey: SigningKey,
    private readonly verificationKeys: SigningKey[],
    private readonly clock: Clock,
    private readonly config: TokenServiceConfig,
  ) {}

  async issueAccessAndId(input: IssueTokenInput): Promise<IssuedCoreTokens> {
    const nowSec = Math.floor(this.clock.now().getTime() / 1000);
    const scope = normalizeScope(input.scope);

    const accessToken = await new SignJWT({ roles: input.roles, scope })
      .setProtectedHeader({ alg: 'RS256', kid: this.activeKey.kid, typ: 'at+jwt' })
      .setIssuer(this.config.issuer)
      .setSubject(input.userId)
      .setAudience(input.clientId)
      .setIssuedAt(nowSec)
      .setExpirationTime(nowSec + this.config.accessTtlSeconds)
      .sign(this.activeKey.privateKey);

    // Profile-claims строго по scope: клиент не получает email/name, если их
    // не запрашивал (OIDC Core 5.4, минимизация данных).
    const scoped = profileForScope(input.profile, scope);
    const idToken = await new SignJWT({
      auth_provider: input.provider,
      email: scoped.email,
      email_verified: scoped.emailVerified,
      name: scoped.name,
      nonce: input.nonce,
    })
      .setProtectedHeader({ alg: 'RS256', kid: this.activeKey.kid })
      .setIssuer(this.config.issuer)
      .setSubject(input.userId)
      .setAudience(input.clientId)
      .setIssuedAt(nowSec)
      .setExpirationTime(nowSec + this.config.idTtlSeconds)
      .sign(this.activeKey.privateKey);

    return { accessToken, idToken, expiresIn: this.config.accessTtlSeconds, scope };
  }

  async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    // Резолвер по kid: токен проверяется тем ключом из набора, чей kid указан
    // в заголовке. Позволяет верифицировать токены, выпущенные до ротации
    // (их ключ ещё в verificationKeys как retired).
    const byKid = new Map(this.verificationKeys.map((k) => [k.kid, k.publicKey]));
    const { payload } = await jwtVerify(
      token,
      (header) => {
        const key = byKid.get(header.kid as string);
        if (!key) throw new Error('unknown kid');
        return key;
      },
      // algorithms закреплён RS256: не даём принять токен с другим алгоритмом
      // подписи (защита от alg-confusion, соответствие discovery). typ=at+jwt
      // (RFC 9068): id_token (без этого заголовка) нельзя предъявить как
      // access-токен. aud намеренно не пиннится: /userinfo принимает токен
      // любого клиента этого issuer — авторизация идёт по sub, не по клиенту.
      {
        issuer: this.config.issuer,
        currentDate: this.clock.now(),
        algorithms: ['RS256'],
        typ: 'at+jwt',
      },
    );
    return payload as unknown as AccessTokenClaims;
  }
}
