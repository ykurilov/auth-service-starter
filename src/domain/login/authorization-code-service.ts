import { randomBytes, randomUUID } from 'node:crypto';
import type { Clock } from '../../ports/clock.js';
import type {
  AuthorizationCodeRecord,
  AuthorizationCodeStore,
  AuthorizationGrant,
  AuthSnapshot,
} from './authorization-code.js';
import { verifyPkceS256 } from './pkce.js';
import { InvalidGrantError } from './errors.js';
import { sha256Hex } from '../shared/hash.js';
import type { ClientType } from '../clients/client.js';

export interface IssueParams {
  clientId: string;
  // Тип клиента в момент решения о согласии (internal — без экрана согласия).
  clientType: ClientType;
  // Регистрация клиента из того же снимка: обмен сверит её с текущей.
  clientRegistrationId?: string;
  userId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  nonce?: string;
  auth: AuthSnapshot;
  // Цепочка SSO браузера, если код выдан по SSO-сессии.
  ssoChainId?: string;
}

export interface RedeemParams {
  code: string;
  clientId: string;
  redirectUri: string;
  codeVerifier: string;
}

export class AuthorizationCodeService {
  constructor(
    private readonly store: AuthorizationCodeStore,
    private readonly clock: Clock,
    private readonly ttlSeconds = 60,
  ) {}

  async issue(params: IssueParams): Promise<string> {
    const code = randomBytes(32).toString('base64url');
    const now = this.clock.now();
    await this.store.save({
      id: randomUUID(),
      codeHash: sha256Hex(code),
      clientId: params.clientId,
      clientType: params.clientType,
      clientRegistrationId: params.clientRegistrationId,
      userId: params.userId,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      scope: params.scope,
      nonce: params.nonce,
      auth: params.auth,
      ...(params.ssoChainId ? { ssoChainId: params.ssoChainId } : {}),
      expiresAt: new Date(now.getTime() + this.ttlSeconds * 1000),
      consumedAt: null,
    });
    return code;
  }

  // Проверяет код (клиент, redirect_uri, PKCE), не гася его. Нужна, чтобы узнать
  // пользователя до обмена, например для лимита. Любой провал -> InvalidGrantError.
  async inspect(params: RedeemParams): Promise<AuthorizationGrant> {
    return toGrant(await this.verified(params));
  }

  // Любой провал -> InvalidGrantError (не раскрываем, какая проверка не прошла).
  async redeem(params: RedeemParams): Promise<AuthorizationGrant> {
    const record = await this.verified(params);
    // Атомарное гашение: при гонке двух обменов выиграет только один.
    if (!(await this.store.consume(record.id, this.clock.now()))) throw new InvalidGrantError();
    return toGrant(record);
  }

  private async verified(params: RedeemParams): Promise<AuthorizationCodeRecord> {
    const record = await this.store.findActiveByHash(sha256Hex(params.code), this.clock.now());
    if (!record) throw new InvalidGrantError();
    if (record.clientId !== params.clientId) throw new InvalidGrantError();
    if (record.redirectUri !== params.redirectUri) throw new InvalidGrantError();
    if (!verifyPkceS256(params.codeVerifier, record.codeChallenge)) {
      throw new InvalidGrantError();
    }
    return record;
  }
}

function toGrant(record: AuthorizationCodeRecord): AuthorizationGrant {
  return {
    userId: record.userId,
    clientId: record.clientId,
    clientType: record.clientType,
    clientRegistrationId: record.clientRegistrationId,
    scope: record.scope,
    nonce: record.nonce,
    auth: record.auth,
    ...(record.ssoChainId ? { ssoChainId: record.ssoChainId } : {}),
  };
}
