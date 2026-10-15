import type { Db } from '../../db/pool.js';
import type {
  EmailSecretRecord,
  EmailSecretStore,
} from '../../../domain/email-secret/email-secret.js';

// Строка email_secrets в snake_case; времена — timestamptz (Date).
interface EmailSecretRow {
  id: string;
  purpose: string;
  email: string;
  secret_hash: string;
  expires_at: Date;
  consumed_at: Date | null;
}

const SELECT_COLUMNS = 'id, purpose, email, secret_hash, expires_at, consumed_at';

// Postgres-реализация EmailSecretStore. Контракт совпадает с in-memory эталоном.
// findActive выбирает свежайший активный секрет по expires_at desc: в схеме нет
// created_at, а при фиксированном TTL более поздний срок истечения = более
// поздний выпуск (как и in-memory эталон, выбирающий max по expiresAt).
// consume — атомарный CAS. Все запросы параметризованы.
export class PgEmailSecretStore implements EmailSecretStore {
  constructor(private readonly db: Db) {}

  private static toRecord(row: EmailSecretRow): EmailSecretRecord {
    return {
      id: row.id,
      purpose: row.purpose,
      email: row.email,
      secretHash: row.secret_hash,
      expiresAt: row.expires_at,
      consumedAt: row.consumed_at ?? null,
    };
  }

  async save(record: EmailSecretRecord): Promise<void> {
    await this.db.query(
      `insert into email_secrets
         (id, purpose, email, secret_hash, expires_at, consumed_at)
       values ($1, $2, $3, $4, $5, $6)`,
      [
        record.id,
        record.purpose,
        record.email,
        record.secretHash,
        record.expiresAt,
        record.consumedAt,
      ],
    );
  }

  async findActive(
    purpose: string,
    email: string,
    now: Date,
  ): Promise<EmailSecretRecord | null> {
    const { rows } = await this.db.query<EmailSecretRow>(
      `select ${SELECT_COLUMNS} from email_secrets
        where purpose = $1 and email = $2 and consumed_at is null and expires_at > $3
        order by expires_at desc
        limit 1`,
      [purpose, email, now],
    );
    return rows[0] ? PgEmailSecretStore.toRecord(rows[0]) : null;
  }

  async consume(id: string, at: Date): Promise<boolean> {
    const { rowCount } = await this.db.query(
      `update email_secrets
          set consumed_at = $2
        where id = $1 and consumed_at is null
        returning id`,
      [id, at],
    );
    return rowCount === 1;
  }

  async invalidateActive(purpose: string, email: string, at: Date): Promise<void> {
    await this.db.query(
      `update email_secrets
          set consumed_at = $3
        where purpose = $1 and email = $2 and consumed_at is null`,
      [purpose, email, at],
    );
  }

  async deleteExpired(before: Date): Promise<number> {
    const { rowCount } = await this.db.query(
      'delete from email_secrets where expires_at < $1',
      [before],
    );
    return rowCount;
  }
}
