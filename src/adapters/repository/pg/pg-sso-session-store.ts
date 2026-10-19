import type { Db } from '../../db/pool.js';
import type { SsoSession, SsoSessionStore, SsoStores } from '../../../domain/sso/sso-session.js';
import { PgSessionStore } from './pg-session-store.js';
import type { AuthSnapshot } from '../../../domain/login/authorization-code.js';

// Строка sso_sessions в snake_case; auth — jsonb, времена — timestamptz (Date).
interface SsoSessionRow {
  id: string;
  user_id: string;
  auth: unknown;
  token_hash: string;
  chain_id: string;
  created_at: Date;
  last_used_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
}

const SELECT_COLUMNS =
  'id, user_id, auth, token_hash, chain_id, created_at, last_used_at, expires_at, revoked_at';

// SsoStores поверх БД: atomically — одна транзакция на оба хранилища.
export function pgSsoStores(db: Db): SsoStores {
  return {
    sso: new PgSsoSessionStore(db),
    sessions: new PgSessionStore(db),
    atomically: (fn) => db.withTransaction((tx) => fn({ sso: new PgSsoSessionStore(tx), sessions: new PgSessionStore(tx) })),
  };
}

// Postgres-реализация SsoSessionStore. Контракт совпадает с in-memory эталоном:
// touch продлевает окно жизни, revoke помечает revoked_at. Все запросы параметризованы.
export class PgSsoSessionStore implements SsoSessionStore {
  constructor(private readonly db: Db) {}

  private static toSession(row: SsoSessionRow): SsoSession {
    return {
      id: row.id,
      userId: row.user_id,
      auth: (row.auth ?? {}) as AuthSnapshot,
      tokenHash: row.token_hash,
      chainId: row.chain_id,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at ?? null,
    };
  }

  async save(session: SsoSession): Promise<void> {
    await this.db.query(
      `insert into sso_sessions
         (id, user_id, auth, token_hash, created_at, last_used_at, expires_at, revoked_at, chain_id, login_id)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        session.id,
        session.userId,
        JSON.stringify(session.auth),
        session.tokenHash,
        session.createdAt,
        session.lastUsedAt,
        session.expiresAt,
        session.revokedAt,
        session.chainId,
        session.auth.loginId ?? null,
      ],
    );
  }

  async findByHash(tokenHash: string): Promise<SsoSession | null> {
    const { rows } = await this.db.query<SsoSessionRow>(
      `select ${SELECT_COLUMNS} from sso_sessions where token_hash = $1`,
      [tokenHash],
    );
    return rows[0] ? PgSsoSessionStore.toSession(rows[0]) : null;
  }

  async findByLogin(loginId: string): Promise<SsoSession | null> {
    const { rows } = await this.db.query<SsoSessionRow>(
      `select ${SELECT_COLUMNS} from sso_sessions where login_id = $1 limit 1`,
      [loginId],
    );
    return rows[0] ? PgSsoSessionStore.toSession(rows[0]) : null;
  }

  async findLatestInChain(chainId: string): Promise<SsoSession | null> {
    const { rows } = await this.db.query<SsoSessionRow>(
      `select ${SELECT_COLUMNS} from sso_sessions where chain_id = $1 order by created_at desc limit 1`,
      [chainId],
    );
    return rows[0] ? PgSsoSessionStore.toSession(rows[0]) : null;
  }

  async holdSignedIn(chainId: string, userId: string): Promise<boolean> {
    const { rowCount } = await this.db.query(
      `select id from sso_sessions
        where chain_id = $1 and user_id = $2 and revoked_at is null
        for share`,
      [chainId, userId],
    );
    return rowCount > 0;
  }

  async touch(id: string, lastUsedAt: Date, expiresAt: Date): Promise<void> {
    await this.db.query(
      'update sso_sessions set last_used_at = $2, expires_at = $3 where id = $1',
      [id, lastUsedAt, expiresAt],
    );
  }

  async revoke(id: string, at: Date): Promise<void> {
    await this.db.query('update sso_sessions set revoked_at = $2 where id = $1', [
      id,
      at,
    ]);
  }

  async revokeChain(chainId: string, at: Date): Promise<void> {
    await this.db.query(
      'update sso_sessions set revoked_at = $2 where chain_id = $1 and revoked_at is null',
      [chainId, at],
    );
  }

  // `revoked_at < $1` уже подразумевает not null (NULL < x -> NULL -> false);
  // без явного `is not null` ещё и потому, что pg-mem теряет строки на этой
  // связке при индексе по колонке (см. PgSessionStore.deleteExpired).
  async deleteExpired(before: Date): Promise<number> {
    const { rowCount } = await this.db.query(
      'delete from sso_sessions where expires_at < $1 or revoked_at < $1',
      [before],
    );
    return rowCount;
  }
}
