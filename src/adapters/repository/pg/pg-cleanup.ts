import type { Db } from '../../db/pool.js';
import type { Clock } from '../../../ports/clock.js';
import { CleanupService } from '../../../domain/maintenance/cleanup-service.js';
import { PgRateLimiter } from '../../ratelimit/pg-rate-limiter.js';
import { PgAuthorizationCodeStore } from './pg-authorization-code-store.js';
import { PgEmailSecretStore } from './pg-email-secret-store.js';
import { PgGoogleNonceStore } from './pg-google-nonce-store.js';
import { PgLoginChallengeStore } from './pg-login-challenge-store.js';
import { PgRefreshTokenStore } from './pg-refresh-token-store.js';
import { PgSessionStore } from './pg-session-store.js';
import { PgSsoSessionStore } from './pg-sso-session-store.js';

// Очистка устаревших данных поверх БД: какие таблицы и чем чистятся.
export function pgCleanupService(db: Db, clock: Clock): CleanupService {
  return new CleanupService(
    new PgAuthorizationCodeStore(db),
    new PgEmailSecretStore(db),
    new PgSessionStore(db),
    new PgRefreshTokenStore(db),
    new PgSsoSessionStore(db),
    clock,
    [new PgLoginChallengeStore(db), new PgGoogleNonceStore(db), new PgRateLimiter(db, clock)],
  );
}
