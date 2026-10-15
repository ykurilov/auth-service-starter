import { randomUUID } from 'node:crypto';
import type { Clock } from '../../ports/clock.js';
import { sha256Hex } from '../shared/hash.js';
import type { AuthSnapshot } from '../login/authorization-code.js';
import { generateSsoToken, type SsoSession, type SsoSessionStore } from './sso-session.js';

export interface SsoSessionServiceConfig { ssoTtlSeconds: number; }

export class SsoSessionService {
  constructor(
    private readonly store: SsoSessionStore,
    private readonly clock: Clock,
    private readonly config: SsoSessionServiceConfig,
  ) {}

  private slide(now: Date): Date { return new Date(now.getTime() + this.config.ssoTtlSeconds * 1000); }

  // previousRawToken — SSO-cookie браузера до этого входа: прежняя сессия
  // отзывается, чтобы в базе не оставалось живых сессий, которые браузер уже
  // заменил (и которые пережили бы смену аккаунта).
  async start(
    userId: string,
    auth: AuthSnapshot,
    previousRawToken?: string | null,
  ): Promise<{ session: SsoSession; rawToken: string }> {
    const now = this.clock.now();
    if (previousRawToken) {
      const previous = await this.store.findByHash(sha256Hex(previousRawToken));
      if (previous && previous.revokedAt === null) await this.store.revoke(previous.id, now);
    }
    const rawToken = generateSsoToken();
    const session: SsoSession = {
      id: randomUUID(), userId, auth, tokenHash: sha256Hex(rawToken),
      createdAt: now, lastUsedAt: now, expiresAt: this.slide(now), revokedAt: null,
    };
    await this.store.save(session);
    return { session, rawToken };
  }

  async resolve(rawToken: string): Promise<SsoSession | null> {
    const now = this.clock.now();
    const session = await this.store.findByHash(sha256Hex(rawToken));
    if (!session || session.revokedAt !== null || session.expiresAt.getTime() <= now.getTime()) return null;
    const expiresAt = this.slide(now);
    await this.store.touch(session.id, now, expiresAt);
    return { ...session, lastUsedAt: now, expiresAt };
  }

  async revoke(sessionId: string): Promise<void> {
    await this.store.revoke(sessionId, this.clock.now());
  }
}
