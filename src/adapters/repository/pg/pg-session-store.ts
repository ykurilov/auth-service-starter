import type { Db } from '../../db/pool.js';
import type {
  Session,
  SessionProfile,
  SessionStore,
  DeviceAudit,
} from '../../../domain/sessions/session.js';

// Строка sessions в snake_case; profile — jsonb, времена — timestamptz (Date).
interface SessionRow {
  id: string;
  user_id: string;
  client_id: string;
  provider: string;
  profile: unknown;
  scope: string;
  device_fingerprint: string;
  ip_hash: string;
  created_at: Date;
  last_used_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  sso_chain_id: string | null;
}

const SELECT_COLUMNS =
  'id, user_id, client_id, provider, profile, scope, device_fingerprint, ip_hash, created_at, last_used_at, expires_at, revoked_at, sso_chain_id';

// Postgres-реализация SessionStore. Контракт совпадает с in-memory эталоном:
// скользящее продление через touch, revoke помечает revoked_at, findActiveByUser
// отсекает отозванные и истёкшие. Все запросы параметризованы.
export class PgSessionStore implements SessionStore {
  constructor(private readonly db: Db) {}

  private static toSession(row: SessionRow): Session {
    const session: Session = {
      id: row.id,
      userId: row.user_id,
      clientId: row.client_id,
      provider: row.provider,
      profile: (row.profile ?? {}) as SessionProfile,
      scope: row.scope,
      deviceFingerprint: row.device_fingerprint,
      ipHash: row.ip_hash,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at ?? null,
    };
    if (row.sso_chain_id !== null && row.sso_chain_id !== undefined) session.ssoChainId = row.sso_chain_id;
    return session;
  }

  async save(session: Session): Promise<void> {
    await this.db.query(
      `insert into sessions
         (id, user_id, client_id, provider, profile, scope, device_fingerprint, ip_hash,
          created_at, last_used_at, expires_at, revoked_at, sso_chain_id)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [
        session.id,
        session.userId,
        session.clientId,
        session.provider,
        JSON.stringify(session.profile),
        session.scope,
        session.deviceFingerprint,
        session.ipHash,
        session.createdAt,
        session.lastUsedAt,
        session.expiresAt,
        session.revokedAt,
        session.ssoChainId ?? null,
      ],
    );
  }

  async findById(id: string): Promise<Session | null> {
    const { rows } = await this.db.query<SessionRow>(
      `select ${SELECT_COLUMNS} from sessions where id = $1`,
      [id],
    );
    return rows[0] ? PgSessionStore.toSession(rows[0]) : null;
  }

  async touch(
    id: string,
    at: Date,
    expiresAt: Date,
    device: DeviceAudit,
  ): Promise<void> {
    await this.db.query(
      `update sessions
          set last_used_at = $2, expires_at = $3, device_fingerprint = $4, ip_hash = $5
        where id = $1`,
      [id, at, expiresAt, device.fingerprint, device.ipHash],
    );
  }

  async revoke(id: string, at: Date): Promise<void> {
    await this.db.query('update sessions set revoked_at = $2 where id = $1', [id, at]);
  }

  async revokeForClient(clientId: string, at: Date, allowedProviders: string[] = []): Promise<void> {
    const params: unknown[] = [clientId, at, ...allowedProviders];
    const retained = allowedProviders.length
      ? ` and provider not in (${allowedProviders.map((_, i) => `$${i + 3}`).join(', ')})` : '';
    await this.db.query(
      `update sessions set revoked_at = $2 where client_id = $1 and revoked_at is null${retained}`,
      params,
    );
  }

  async revokeForUser(userId: string, at: Date): Promise<void> {
    await this.db.query(
      'update sessions set revoked_at = $2 where user_id = $1 and revoked_at is null',
      [userId, at],
    );
  }

  async revokeForSsoChain(chainId: string, at: Date, userId?: string): Promise<void> {
    await this.db.query(
      `update sessions set revoked_at = $2
        where revoked_at is null and (sso_chain_id = $1 or user_id = $3)`,
      [chainId, at, userId ?? null],
    );
  }

  async findActiveByUser(userId: string, now: Date): Promise<Session[]> {
    const { rows } = await this.db.query<SessionRow>(
      `select ${SELECT_COLUMNS}
         from sessions
        where user_id = $1 and revoked_at is null and expires_at > $2`,
      [userId, now],
    );
    return rows.map((r) => PgSessionStore.toSession(r));
  }

  // refresh_tokens.session_id references sessions(id) БЕЗ on delete cascade —
  // сначала гасим их вручную, затем сами сессии, одной транзакцией.
  // `revoked_at < $1` уже подразумевает not null (NULL < x -> NULL -> false);
  // явное `is not null and` не пишем ещё и потому, что pg-mem в контрактных
  // тестах теряет строки на этой связке при наличии индекса по revoked_at.
  async deleteExpired(before: Date): Promise<number> {
    return this.db.withTransaction(async (tx) => {
      await tx.query(
        `delete from refresh_tokens
          where session_id in (
            select id from sessions
             where expires_at < $1 or revoked_at < $1
          )`,
        [before],
      );
      const { rowCount } = await tx.query(
        'delete from sessions where expires_at < $1 or revoked_at < $1',
        [before],
      );
      return rowCount;
    });
  }
}
