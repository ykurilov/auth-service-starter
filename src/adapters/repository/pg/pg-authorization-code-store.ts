import type { Db } from '../../db/pool.js';
import type {
  AuthSnapshot,
  AuthorizationCodeRecord,
  AuthorizationCodeStore,
} from '../../../domain/login/authorization-code.js';

// Строка authorization_codes в snake_case. auth — jsonb (читается объектом),
// nonce — nullable, времена — timestamptz (Date).
interface AuthorizationCodeRow {
  id: string;
  code_hash: string;
  client_id: string;
  user_id: string;
  redirect_uri: string;
  code_challenge: string;
  scope: string;
  nonce: string | null;
  auth: AuthSnapshot;
  expires_at: Date;
  consumed_at: Date | null;
}

const SELECT_COLUMNS =
  'id, code_hash, client_id, user_id, redirect_uri, code_challenge, scope, nonce, auth, expires_at, consumed_at';

// Postgres-реализация AuthorizationCodeStore. Контракт совпадает с in-memory
// эталоном. consume — атомарный CAS. Все запросы параметризованы.
export class PgAuthorizationCodeStore implements AuthorizationCodeStore {
  constructor(private readonly db: Db) {}

  private static toRecord(row: AuthorizationCodeRow): AuthorizationCodeRecord {
    const record: AuthorizationCodeRecord = {
      id: row.id,
      codeHash: row.code_hash,
      clientId: row.client_id,
      userId: row.user_id,
      redirectUri: row.redirect_uri,
      codeChallenge: row.code_challenge,
      scope: row.scope,
      auth: row.auth,
      expiresAt: row.expires_at,
      consumedAt: row.consumed_at ?? null,
    };
    // nonce optional: колонка nullable, null => поле опускаем (как in-memory).
    if (row.nonce !== null) record.nonce = row.nonce;
    return record;
  }

  async save(record: AuthorizationCodeRecord): Promise<void> {
    await this.db.query(
      `insert into authorization_codes
         (id, code_hash, client_id, user_id, redirect_uri, code_challenge, scope, nonce, auth, expires_at, consumed_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        record.id,
        record.codeHash,
        record.clientId,
        record.userId,
        record.redirectUri,
        record.codeChallenge,
        record.scope,
        record.nonce ?? null,
        JSON.stringify(record.auth),
        record.expiresAt,
        record.consumedAt,
      ],
    );
  }

  async findActiveByHash(
    codeHash: string,
    now: Date,
  ): Promise<AuthorizationCodeRecord | null> {
    const { rows } = await this.db.query<AuthorizationCodeRow>(
      `select ${SELECT_COLUMNS} from authorization_codes
        where code_hash = $1 and consumed_at is null and expires_at > $2`,
      [codeHash, now],
    );
    return rows[0] ? PgAuthorizationCodeStore.toRecord(rows[0]) : null;
  }

  async consume(id: string, at: Date): Promise<boolean> {
    const { rowCount } = await this.db.query(
      `update authorization_codes
          set consumed_at = $2
        where id = $1 and consumed_at is null
        returning id`,
      [id, at],
    );
    return rowCount === 1;
  }

  async deleteExpired(before: Date): Promise<number> {
    const { rowCount } = await this.db.query(
      'delete from authorization_codes where expires_at < $1',
      [before],
    );
    return rowCount;
  }
}
