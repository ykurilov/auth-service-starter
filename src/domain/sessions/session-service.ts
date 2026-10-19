import { randomUUID } from 'node:crypto';
import type { Clock } from '../../ports/clock.js';
import type { TokenService } from '../tokens/token-service.js';
import { sha256Hex } from '../shared/hash.js';
import { normalizeScope } from '../tokens/scope.js';
import type { Session, SessionProfile, SessionStore } from './session.js';
import type { RefreshTokenRecord, RefreshTokenStore } from './refresh-token.js';
import { deriveRefreshToken, generateRefreshFamily, generateRefreshToken, refreshFamilyOf } from './refresh-token.js';
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
  // Цепочка SSO браузера, через которую выдан код (см. SsoSession.chainId).
  ssoChainId?: string;
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
      ...(params.ssoChainId ? { ssoChainId: params.ssoChainId } : {}),
    };
    await this.sessions.save(session);

    const family = generateRefreshFamily();
    const raw = `${family}.${generateRefreshToken()}`;
    await this.refreshTokens.save({
      id: randomUUID(),
      sessionId: session.id,
      tokenHash: sha256Hex(raw),
      previousTokenId: null,
      replacedById: null,
      createdAt: now,
      consumedAt: null,
      familyHash: sha256Hex(family),
    });

    const core = await this.issueFor(session, params.roles, params.nonce);
    return { ...core, refreshToken: raw, sessionId: session.id };
  }

  // Possession of a real secret supplies the trusted session/rate-limit key.
  async resolveRefreshSession(rawToken: string): Promise<Session> {
    const found = await this.lookup(rawToken);
    if (!found) throw new InvalidRefreshTokenError();
    return this.activeSession(found.sessionId);
  }

  // Запись токена, а если её строку уже удалила очистка истории — сессия по
  // семейству токена (record: null). Очистка удаляет только токены, погашенные
  // давно (см. REFRESH_HISTORY_RETENTION_MS), поэтому такой токен — повтор
  // погашенного старше окна grace.
  private async lookup(rawToken: string): Promise<{ sessionId: string; record: RefreshTokenRecord | null } | null> {
    const record = await this.refreshTokens.findByHash(sha256Hex(rawToken));
    if (record) return { sessionId: record.sessionId, record };
    const family = refreshFamilyOf(rawToken);
    const sessionId = family ? await this.refreshTokens.findSessionIdByFamily(sha256Hex(family)) : null;
    return sessionId ? { sessionId, record: null } : null;
  }

  private async activeSession(id: string): Promise<Session> {
    const session = await this.sessions.findById(id);
    if (!session || session.revokedAt !== null || session.expiresAt.getTime() <= this.clock.now().getTime()) {
      throw new InvalidRefreshTokenError();
    }
    return session;
  }

  // notAfter — дальше какого момента сессию не продлевать (срок, до которого
  // браузер её SSO-цепочки может её найти для выхода). Прошёл — refresh
  // отклоняется, как у истёкшей сессии.
  async refresh(rawToken: string, device: DeviceInfo, roles?: string[], notAfter?: Date): Promise<IssuedTokens> {
    const now = this.clock.now();
    const found = await this.lookup(rawToken);
    if (!found) throw new InvalidRefreshTokenError();
    const session = await this.activeSession(found.sessionId);
    if (notAfter && notAfter.getTime() <= now.getTime()) throw new InvalidRefreshTokenError();
    if (!found.record) {
      await this.sessions.revoke(session.id, now);
      throw new RefreshTokenReuseError();
    }
    let record: RefreshTokenRecord | null = found.record;

    if (record.consumedAt === null) {
      const newId = randomUUID();
      const raw = deriveRefreshToken(rawToken, newId);
      const won = await this.refreshTokens.rotate(record.id, {
        id: newId, sessionId: session.id, tokenHash: sha256Hex(raw),
        previousTokenId: record.id, replacedById: null, createdAt: now,
        consumedAt: null, derivationVersion: 'hmac-sha256-v2', familyHash: sha256Hex(refreshFamilyOf(raw)!),
      }, now);
      if (won) {
        const slid = this.slideExpiry(now);
        const expiresAt = notAfter && notAfter.getTime() < slid.getTime() ? notAfter : slid;
        await this.sessions.touch(session.id, now, expiresAt, {
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
          !successor.derivationVersion) {
        // A random legacy successor cannot be reconstructed. During grace
        // reject the retry without revoking its still valid current session.
        throw new InvalidRefreshTokenError();
      }
      raw = deriveRefreshToken(raw, successor.id, successor.derivationVersion);
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
  // В том числе токен, чью строку уже удалила очистка: его находит семейство.
  async revokeByRefreshToken(rawToken: string): Promise<void> {
    const found = await this.lookup(rawToken);
    if (!found) return;
    await this.sessions.revoke(found.sessionId, this.clock.now());
  }

  async revokeForClient(clientId: string, allowedProviders: string[] = []): Promise<void> {
    await this.sessions.revokeForClient(clientId, this.clock.now(), allowedProviders);
  }

  // Отзыв всех живых сессий пользователя во всех клиентах и браузерах.
  // «Выйти» им не пользуется: он гасит только цепочку своего браузера.
  async revokeAllForUser(userId: string): Promise<void> {
    await this.sessions.revokeForUser(userId, this.clock.now());
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
