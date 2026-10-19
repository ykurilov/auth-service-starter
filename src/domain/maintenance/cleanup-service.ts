import type { Clock } from '../../ports/clock.js';
import type { AuthorizationCodeStore } from '../login/authorization-code.js';
import type { EmailSecretStore } from '../email-secret/email-secret.js';
import type { SessionStore } from '../sessions/session.js';
import {
  REFRESH_HISTORY_KEEP_LATEST,
  REFRESH_HISTORY_RETENTION_MS,
  type RefreshTokenStore,
} from '../sessions/refresh-token.js';
import type { SsoSessionStore } from '../sso/sso-session.js';

export interface CleanupCounts {
  codes: number;
  emailSecrets: number;
  sessions: number;
  // Давно погашенные refresh-токены живых сессий.
  refreshHistory: number;
  ssoSessions: number;
  // Попытки входа по коду, nonce Google, счётчики лимитов — суммарно.
  shortLived: number;
}

// Хранилище короткоживущих записей, которые после истечения бесполезны.
export interface ExpiringStore {
  deleteExpired(before: Date): Promise<number>;
}

const SESSION_RETENTION_MS = 30 * 24 * 3600 * 1000;

// Одноразовые секреты (коды, email-коды) после истечения бесполезны — чистим
// сразу. Сессии храним ещё 30 дней после истечения/отзыва: журнал для разбора
// инцидентов. Refresh-токены уходят вместе со своей сессией, а у живой сессии
// от истории ротаций остаётся только нужное для обнаружения повтора (см.
// REFRESH_HISTORY_RETENTION_MS): на сессию — токены за последний час, но не
// меньше нескольких последних.
export class CleanupService {
  constructor(
    private readonly codes: AuthorizationCodeStore,
    private readonly emailSecrets: EmailSecretStore,
    private readonly sessions: SessionStore,
    private readonly refreshTokens: Pick<RefreshTokenStore, 'pruneHistory'>,
    private readonly sso: SsoSessionStore,
    private readonly clock: Clock,
    private readonly shortLived: ExpiringStore[] = [],
  ) {}

  async runOnce(): Promise<CleanupCounts> {
    const now = this.clock.now();
    const sessionsBefore = new Date(now.getTime() - SESSION_RETENTION_MS);
    return {
      codes: await this.codes.deleteExpired(now),
      emailSecrets: await this.emailSecrets.deleteExpired(now),
      sessions: await this.sessions.deleteExpired(sessionsBefore),
      refreshHistory: await this.refreshTokens.pruneHistory(
        new Date(now.getTime() - REFRESH_HISTORY_RETENTION_MS), REFRESH_HISTORY_KEEP_LATEST),
      ssoSessions: await this.sso.deleteExpired(sessionsBefore),
      shortLived: await this.deleteShortLived(now),
    };
  }

  private async deleteShortLived(now: Date): Promise<number> {
    let total = 0;
    for (const store of this.shortLived) total += await store.deleteExpired(now);
    return total;
  }
}
