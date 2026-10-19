import { randomUUID } from 'node:crypto';
import type { Clock } from '../../ports/clock.js';
import { sha256Hex } from '../shared/hash.js';
import type { AuthSnapshot } from '../login/authorization-code.js';
import { generateSsoToken, type SsoSession, type SsoSessionStore, type SsoStores } from './sso-session.js';

export interface SsoSessionServiceConfig { ssoTtlSeconds: number; }

// Цепочка браузера, через которую выдан код входа loginId; null — вход без
// SSO-сессии (код выдан до обновления), к цепочке не привязан.
export async function chainOfLogin(sso: SsoSessionStore, loginId: string | undefined): Promise<string | null> {
  if (!loginId) return null;
  return (await sso.findByLogin(loginId))?.chainId ?? null;
}

export class SsoSessionService {
  constructor(
    private readonly stores: SsoStores,
    private readonly clock: Clock,
    private readonly config: SsoSessionServiceConfig,
  ) {}

  private slide(now: Date): Date { return new Date(now.getTime() + this.config.ssoTtlSeconds * 1000); }

  // previousRawToken — SSO-cookie браузера до этого входа. Новая сессия
  // продолжает её цепочку, прежние сессии цепочки отзываются. Вошёл другой
  // пользователь — гаснут и сессии приложений, выданные через цепочку: в
  // браузере не остаётся прежнего аккаунта ни в одном приложении. На других
  // устройствах прежний пользователь остаётся.
  async start(
    userId: string,
    auth: AuthSnapshot,
    previousRawToken?: string | null,
  ): Promise<{ session: SsoSession; rawToken: string }> {
    const now = this.clock.now();
    const rawToken = generateSsoToken();
    return this.stores.atomically(async ({ sso, sessions }) => {
      const previous = previousRawToken ? await sso.findByHash(sha256Hex(previousRawToken)) : null;
      const chainId = previous?.chainId ?? randomUUID();
      if (previous) {
        await sso.revokeChain(chainId, now);
        if (previous.userId !== userId) await sessions.revokeForSsoChain(chainId, now);
      }
      const session: SsoSession = {
        id: randomUUID(), userId, auth, tokenHash: sha256Hex(rawToken), chainId,
        createdAt: now, lastUsedAt: now, expiresAt: this.slide(now), revokedAt: null,
      };
      await sso.save(session);
      return { session, rawToken };
    });
  }

  async resolve(rawToken: string): Promise<SsoSession | null> {
    const now = this.clock.now();
    const session = await this.stores.sso.findByHash(sha256Hex(rawToken));
    if (!session || session.revokedAt !== null || session.expiresAt.getTime() <= now.getTime()) return null;
    const expiresAt = this.slide(now);
    await this.stores.sso.touch(session.id, now, expiresAt);
    return { ...session, lastUsedAt: now, expiresAt };
  }

  async revoke(sessionId: string): Promise<void> {
    await this.stores.sso.revoke(sessionId, this.clock.now());
  }

  // Выход во всех приложениях: гасит цепочку SSO браузера и сессии
  // приложений, выданные через неё (какого бы пользователя они ни были), а
  // живая cookie — ещё и все сессии своего пользователя на любых устройствах.
  // Одной транзакцией. Отозванная или истёкшая cookie только доделывает отзыв
  // своей цепочки (повтор после сбоя) и только если браузер не сменил её
  // новым входом: старая cookie не гасит сессии на других устройствах.
  async signOut(rawToken: string): Promise<void> {
    const now = this.clock.now();
    await this.stores.atomically(async ({ sso, sessions }) => {
      const session = await sso.findByHash(sha256Hex(rawToken));
      if (!session) return;
      const live = session.revokedAt === null && session.expiresAt.getTime() > now.getTime();
      if (!live && (await sso.findLatestInChain(session.chainId))?.id !== session.id) return;
      await sso.revokeChain(session.chainId, now);
      await sessions.revokeForSsoChain(session.chainId, now, live ? session.userId : undefined);
    });
  }
}
