import { randomBytes, randomUUID } from 'node:crypto';
import type { Clock } from '../../ports/clock.js';
import type {
  AuthorizationCodeStore,
  AuthorizationGrant,
  AuthSnapshot,
} from './authorization-code.js';
import { verifyPkceS256 } from './pkce.js';
import { InvalidGrantError } from './errors.js';
import { sha256Hex } from '../shared/hash.js';

export interface IssueParams {
  clientId: string;
  userId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  nonce?: string;
  auth: AuthSnapshot;
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
      userId: params.userId,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      scope: params.scope,
      nonce: params.nonce,
      auth: params.auth,
      expiresAt: new Date(now.getTime() + this.ttlSeconds * 1000),
      consumedAt: null,
    });
    return code;
  }

  // Любой провал -> InvalidGrantError (не раскрываем, какая проверка не прошла).
  async redeem(params: RedeemParams): Promise<AuthorizationGrant> {
    const now = this.clock.now();
    const record = await this.store.findActiveByHash(sha256Hex(params.code), now);
    if (!record) throw new InvalidGrantError();
    if (record.clientId !== params.clientId) throw new InvalidGrantError();
    if (record.redirectUri !== params.redirectUri) throw new InvalidGrantError();
    if (!verifyPkceS256(params.codeVerifier, record.codeChallenge)) {
      throw new InvalidGrantError();
    }
    // Атомарное гашение: при гонке двух обменов выиграет только один.
    if (!(await this.store.consume(record.id, now))) throw new InvalidGrantError();
    return {
      userId: record.userId,
      clientId: record.clientId,
      scope: record.scope,
      nonce: record.nonce,
      auth: record.auth,
    };
  }
}
