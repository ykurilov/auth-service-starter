import { randomUUID } from 'node:crypto';
import type { Clock } from '../../ports/clock.js';
import type { TokenService } from '../tokens/token-service.js';
import { sha256Hex } from '../shared/hash.js';
import { normalizeScope } from '../tokens/scope.js';
import type { Session, SessionProfile, SessionStore } from './session.js';
import type { RefreshTokenRecord, RefreshTokenStore } from './refresh-token.js';
import { deriveRefreshToken, generateRefreshToken } from './refresh-token.js';
import type { DeviceInfo } from './device.js';
import { fingerprintDevice, hashIp } from './device.js';
import { InvalidRefreshTokenError, RefreshTokenReuseError } from './errors.js';

export interface SessionServiceConfig {
  refreshTtlSeconds: number;
  // Окно, в течение которого повторное предъявление уже погашенного токена
  // считается легитимной гонкой (параллельные вкладки/ретраи), а не угоном.
  // Необязателен: по умолчанию 60 000 мс.
  refreshReuseGraceMs?: number;
}

export interface StartParams {
  userId: string;
  clientId: string;
  provider: string;
  profile: SessionProfile;
  scope: string;
  roles?: string[];
  device: DeviceInfo;
  // nonce из authorization request: попадает в первый id_token и не хранится
  // в сессии — при refresh-ротации id_token выпускается уже без него.
  nonce?: string;
}

export interface IssuedTokens {
  accessToken: string;
  idToken: string;
  refreshToken: string;
  expiresIn: number;
  scope: string;
  sessionId: string;
}

export class SessionService {
  // Защита от бесконечного/аномально длинного прохода по цепочке ротаций.
  private static readonly MAX_CHAIN_DEPTH = 32;

  private get reuseGraceMs(): number {
    return this.config.refreshReuseGraceMs ?? 60_000;
  }

  constructor(
    private readonly sessions: SessionStore,
    private readonly refreshTokens: RefreshTokenStore,
    private readonly tokens: TokenService,
    private readonly clock: Clock,
    private readonly config: SessionServiceConfig,
  ) {}

  async start(params: StartParams): Promise<IssuedTokens> {
    const now = this.clock.now();
    const session: Session = {
      id: randomUUID(),
      userId: params.userId,
      clientId: params.clientId,
      provider: params.provider,
      profile: params.profile,
      scope: normalizeScope(params.scope),
      deviceFingerprint: fingerprintDevice(params.device),
      ipHash: hashIp(params.device.ip),
      createdAt: now,
      lastUsedAt: now,
      expiresAt: this.slideExpiry(now),
      revokedAt: null,
    };
    await this.sessions.save(session);

    const raw = generateRefreshToken();
    await this.refreshTokens.save({
      id: randomUUID(),
      sessionId: session.id,
      tokenHash: sha256Hex(raw),
      previousTokenId: null,
      replacedById: null,
      createdAt: now,
      consumedAt: null,
    });

    const core = await this.issueFor(session, params.roles, params.nonce);
    return { ...core, refreshToken: raw, sessionId: session.id };
  }

  // Possession of a real secret supplies the trusted session/rate-limit key.
  async resolveRefreshSession(rawToken: string): Promise<Session> {
    const record = await this.refreshTokens.findByHash(sha256Hex(rawToken));
    if (!record) throw new InvalidRefreshTokenError();
    return this.activeSession(record.sessionId);
  }

  private async activeSession(id: string): Promise<Session> {
    const session = await this.sessions.findById(id);
    if (!session || session.revokedAt !== null || session.expiresAt.getTime() <= this.clock.now().getTime()) {
      throw new InvalidRefreshTokenError();
    }
    return session;
  }

  async refresh(rawToken: string, device: DeviceInfo, roles?: string[]): Promise<IssuedTokens> {
    const now = this.clock.now();
    let record = await this.refreshTokens.findByHash(sha256Hex(rawToken));
    if (!record) throw new InvalidRefreshTokenError();
    const session = await this.activeSession(record.sessionId);

    if (record.consumedAt === null) {
      const newId = randomUUID();
      const raw = deriveRefreshToken(rawToken, newId);
      const won = await this.refreshTokens.rotate(record.id, {
        id: newId, sessionId: session.id, tokenHash: sha256Hex(raw),
        previousTokenId: record.id, replacedById: null, createdAt: now,
        consumedAt: null, derivationVersion: 'hmac-sha256-v1',
      }, now);
      if (won) {
        await this.sessions.touch(session.id, now, this.slideExpiry(now), {
          fingerprint: fingerprintDevice(device), ipHash: hashIp(device.ip),
        });
        await this.activeSession(session.id);
        return { ...await this.issueFor(session, roles), refreshToken: raw, sessionId: session.id };
      }
      // Atomic publication: the CAS loser can reread the complete winner.
      record = await this.refreshTokens.findById(record.id);
      if (!record) throw new InvalidRefreshTokenError();
    }

    if (!record.consumedAt) throw new InvalidRefreshTokenError();
    if (this.clock.now().getTime() - record.consumedAt.getTime() > this.reuseGraceMs) {
      await this.sessions.revoke(session.id, this.clock.now());
      throw new RefreshTokenReuseError();
    }

    // Recover the published result without rotation. If another exchange has
    // advanced it, derive forward to the current live head without writes.
    let raw = rawToken;
    for (let depth = 0; depth < SessionService.MAX_CHAIN_DEPTH; depth++) {
      const successor: RefreshTokenRecord | null = record.replacedById
        ? await this.refreshTokens.findById(record.replacedById) : null;
      if (!successor || successor.sessionId !== session.id || successor.previousTokenId !== record.id ||
          successor.derivationVersion !== 'hmac-sha256-v1') {
        // A random legacy successor cannot be reconstructed. During grace
        // reject the retry without revoking its still valid current session.
        throw new InvalidRefreshTokenError();
      }
      raw = deriveRefreshToken(raw, successor.id);
      if (sha256Hex(raw) !== successor.tokenHash) throw new InvalidRefreshTokenError();
      if (successor.consumedAt === null) {
        await this.activeSession(session.id);
        return { ...await this.issueFor(session, roles), refreshToken: raw, sessionId: session.id };
      }
      record = successor;
    }
    throw new InvalidRefreshTokenError();
  }

  async revoke(sessionId: string): Promise<void> {
    await this.sessions.revoke(sessionId, this.clock.now());
  }

  // RFC 7009: отзыв по предъявленному refresh-токену. Неизвестный токен — не
  // ошибка (иначе эндпоинт стал бы оракулом существования токенов).
  // consumedAt намеренно не проверяем: любой исторический токен цепочки ротации
  // тоже гасит сессию — клиент, потерявший актуальную голову, всё равно выйдет.
  async revokeByRefreshToken(rawToken: string): Promise<void> {
    const record = await this.refreshTokens.findByHash(sha256Hex(rawToken));
    if (!record) return;
    await this.sessions.revoke(record.sessionId, this.clock.now());
  }

  async revokeForClient(clientId: string, allowedProviders: string[] = []): Promise<void> {
    await this.sessions.revokeForClient(clientId, this.clock.now(), allowedProviders);
  }

  // SSO logout приложения: гасим все живые device-сессии пользователя в этом клиенте.
  async revokeAllForUserClient(userId: string, clientId: string): Promise<void> {
    const active = await this.sessions.findActiveByUser(userId, this.clock.now());
    for (const s of active) {
      if (s.clientId === clientId) await this.sessions.revoke(s.id, this.clock.now());
    }
  }

  async listForUser(userId: string): Promise<Session[]> {
    return this.sessions.findActiveByUser(userId, this.clock.now());
  }

  private slideExpiry(now: Date): Date {
    return new Date(now.getTime() + this.config.refreshTtlSeconds * 1000);
  }

  private async issueFor(session: Session, roles?: string[], nonce?: string) {
    return this.tokens.issueAccessAndId({
      userId: session.userId,
      clientId: session.clientId,
      provider: session.provider,
      roles: roles ?? [],
      profile: session.profile,
      // scope хранится в сессии, поэтому refresh-ротация перевыпускает токены
      // с тем же набором scope, что был одобрен при первичном входе.
      scope: session.scope,
      nonce,
    });
  }
}
