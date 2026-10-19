import type { Db } from '../../db/pool.js';
import type {
  LoginChallengeRecord,
  LoginChallengeStore,
} from '../../../domain/email-login/login-challenge.js';

interface ChallengeRow {
  id: string;
  handle_hash: string;
  binding_hash: string;
  email: string;
  client_id: string | null;
  client_registration_id: string | null;
  code_hash: string;
  attempts: number;
  max_attempts: number;
  resends: number;
  max_resends: number;
  link_provider: string | null;
  link_subject: string | null;
  link_name: string | null;
  created_at: Date;
  expires_at: Date;
  consumed_at: Date | null;
}

const COLUMNS =
  'id, handle_hash, binding_hash, email, code_hash, attempts, max_attempts, resends, max_resends, ' +
  'link_provider, link_subject, link_name, created_at, expires_at, consumed_at, ' +
  'client_id, client_registration_id';

// Postgres-реализация LoginChallengeStore. Ограничения попыток и переотправок
// выражены в WHERE одиночного UPDATE ... RETURNING: Postgres берёт блокировку
// строки и перепроверяет условие на свежей версии, поэтому параллельные
// проверки (в т.ч. с разных экземпляров сервиса) не превысят лимит.
export class PgLoginChallengeStore implements LoginChallengeStore {
  constructor(private readonly db: Db) {}

  private static toRecord(row: ChallengeRow): LoginChallengeRecord {
    return {
      id: row.id,
      handleHash: row.handle_hash,
      bindingHash: row.binding_hash,
      email: row.email,
      clientId: row.client_id ?? null,
      clientRegistrationId: row.client_registration_id ?? null,
      codeHash: row.code_hash,
      attempts: Number(row.attempts),
      maxAttempts: Number(row.max_attempts),
      resends: Number(row.resends),
      maxResends: Number(row.max_resends),
      link:
        row.link_provider && row.link_subject
          ? {
              provider: row.link_provider,
              subject: row.link_subject,
              ...(row.link_name ? { name: row.link_name } : {}),
            }
          : null,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      consumedAt: row.consumed_at ?? null,
    };
  }

  async create(r: LoginChallengeRecord): Promise<void> {
    await this.db.query(
      `insert into email_login_challenges (${COLUMNS})
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
      [
        r.id, r.handleHash, r.bindingHash, r.email, r.codeHash, r.attempts, r.maxAttempts,
        r.resends, r.maxResends, r.link?.provider ?? null, r.link?.subject ?? null,
        r.link?.name ?? null, r.createdAt, r.expiresAt, r.consumedAt,
        r.clientId, r.clientRegistrationId,
      ],
    );
  }

  async find(handleHash: string, bindingHash: string, now: Date): Promise<LoginChallengeRecord | null> {
    const { rows } = await this.db.query<ChallengeRow>(
      `select ${COLUMNS} from email_login_challenges
        where handle_hash = $1 and binding_hash = $2 and consumed_at is null and expires_at > $3`,
      [handleHash, bindingHash, now],
    );
    return rows[0] ? PgLoginChallengeStore.toRecord(rows[0]) : null;
  }

  async claimAttempt(handleHash: string, bindingHash: string, now: Date): Promise<LoginChallengeRecord | null> {
    const { rows } = await this.db.query<ChallengeRow>(
      `update email_login_challenges
          set attempts = attempts + 1
        where handle_hash = $1 and binding_hash = $2 and consumed_at is null
          and expires_at > $3 and attempts < max_attempts
        returning ${COLUMNS}`,
      [handleHash, bindingHash, now],
    );
    return rows[0] ? PgLoginChallengeStore.toRecord(rows[0]) : null;
  }

  async reserveResend(handleHash: string, bindingHash: string, now: Date): Promise<LoginChallengeRecord | null> {
    const { rows } = await this.db.query<ChallengeRow>(
      `update email_login_challenges
          set resends = resends + 1
        where handle_hash = $1 and binding_hash = $2 and consumed_at is null
          and expires_at > $3 and resends < max_resends and attempts < max_attempts
        returning ${COLUMNS}`,
      [handleHash, bindingHash, now],
    );
    return rows[0] ? PgLoginChallengeStore.toRecord(rows[0]) : null;
  }

  async replaceCode(id: string, codeHash: string, expiresAt: Date, now: Date): Promise<boolean> {
    const { rowCount } = await this.db.query(
      `update email_login_challenges set code_hash = $2, expires_at = $3
        where id = $1 and consumed_at is null and expires_at > $4 returning id`,
      [id, codeHash, expiresAt, now],
    );
    return rowCount === 1;
  }

  async releaseResend(id: string): Promise<void> {
    await this.db.query(
      'update email_login_challenges set resends = resends - 1 where id = $1 and resends > 0',
      [id],
    );
  }

  async consume(id: string, at: Date): Promise<boolean> {
    const { rowCount } = await this.db.query(
      `update email_login_challenges set consumed_at = $2
        where id = $1 and consumed_at is null returning id`,
      [id, at],
    );
    return rowCount === 1;
  }

  async deleteExpired(before: Date): Promise<number> {
    const { rowCount } = await this.db.query(
      'delete from email_login_challenges where expires_at < $1',
      [before],
    );
    return rowCount;
  }
}
