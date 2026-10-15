import type { Db } from '../../db/pool.js';
import type {
  RefreshTokenRecord,
  RefreshTokenStore,
} from '../../../domain/sessions/refresh-token.js';

// Строка refresh_tokens в snake_case; времена — timestamptz (Date).
interface RefreshTokenRow {
  id: string;
  session_id: string;
  token_hash: string;
  previous_token_id: string | null;
  replaced_by_id: string | null;
  created_at: Date;
  consumed_at: Date | null;
  derivation_version: RefreshTokenRecord['derivationVersion'] | null;
}

const SELECT_COLUMNS =
  'id, session_id, token_hash, previous_token_id, replaced_by_id, created_at, consumed_at, derivation_version';

// Postgres-реализация RefreshTokenStore. Контракт совпадает с in-memory эталоном.
// consume — атомарный CAS: гасит только непогашенный токен, возвращает выиграл ли
// вызов гонку. Все запросы параметризованы.
export class PgRefreshTokenStore implements RefreshTokenStore {
  constructor(private readonly db: Db) {}

  private static toRecord(row: RefreshTokenRow): RefreshTokenRecord {
    return {
      id: row.id,
      sessionId: row.session_id,
      tokenHash: row.token_hash,
      previousTokenId: row.previous_token_id ?? null,
      replacedById: row.replaced_by_id ?? null,
      createdAt: row.created_at,
      consumedAt: row.consumed_at ?? null,
      ...(row.derivation_version ? { derivationVersion: row.derivation_version } : {}),
    };
  }

  async save(record: RefreshTokenRecord): Promise<void> {
    await this.db.query(
      `insert into refresh_tokens
         (id, session_id, token_hash, previous_token_id, replaced_by_id, created_at, consumed_at, derivation_version)
       values ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        record.id,
        record.sessionId,
        record.tokenHash,
        record.previousTokenId,
        record.replacedById,
        record.createdAt,
        record.consumedAt,
        record.derivationVersion ?? null,
      ],
    );
  }

  async findByHash(tokenHash: string): Promise<RefreshTokenRecord | null> {
    const { rows } = await this.db.query<RefreshTokenRow>(
      `select ${SELECT_COLUMNS} from refresh_tokens where token_hash = $1`,
      [tokenHash],
    );
    return rows[0] ? PgRefreshTokenStore.toRecord(rows[0]) : null;
  }

  async findById(id: string): Promise<RefreshTokenRecord | null> {
    const { rows } = await this.db.query<RefreshTokenRow>(
      `select ${SELECT_COLUMNS} from refresh_tokens where id = $1`,
      [id],
    );
    return rows[0] ? PgRefreshTokenStore.toRecord(rows[0]) : null;
  }

  async rotate(headId: string, successor: RefreshTokenRecord, at: Date): Promise<boolean> {
    return this.db.withTransaction(async (tx) => {
      // The row lock makes a concurrent loser wait for the full committed pair.
      const { rowCount } = await tx.query(
        `update refresh_tokens set consumed_at = $3, replaced_by_id = $2
          where id = $1 and session_id = $4 and consumed_at is null returning id`,
        [headId, successor.id, at, successor.sessionId],
      );
      if (rowCount !== 1) return false;
      if (successor.previousTokenId !== headId) throw new Error('invalid refresh predecessor');
      await new PgRefreshTokenStore(tx).save(successor);
      return true;
    });
  }

  async consume(id: string, replacedById: string, at: Date): Promise<boolean> {
    const { rowCount } = await this.db.query(
      `update refresh_tokens
          set consumed_at = $3, replaced_by_id = $2
        where id = $1 and consumed_at is null
        returning id`,
      [id, replacedById, at],
    );
    return rowCount === 1;
  }
}
