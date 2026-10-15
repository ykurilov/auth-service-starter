import { createHash, randomUUID } from 'node:crypto';
import type { Db } from '../../db/pool.js';
import {
  IdentityConflictError,
  type IdentityRepository,
} from '../../../domain/identity/identity-repository.js';
import type { User, Identity, EmailAddress } from '../../../domain/identity/user.js';
import { normalizeEmail } from '../../../domain/identity/user.js';

// Строки БД в snake_case; доменные типы в camelCase. timestamptz приходит как Date.
interface UserRow {
  id: string;
  display_name: string | null;
  status: string;
  created_at: Date;
}

interface IdentityRow {
  id: string;
  user_id: string;
  provider: string;
  subject: string;
  created_at: Date;
}

interface EmailRow {
  id: string;
  user_id: string;
  email: string;
  verified: boolean;
  created_at: Date;
}

// Postgres-реализация IdentityRepository. Идентична по контракту in-memory эталону:
// статус нового пользователя 'active', email нормализуется, uuid генерируется в коде
// (randomUUID) ради совместимости с pg-mem. Все запросы параметризованы.
export class PgIdentityRepository implements IdentityRepository {
  constructor(private readonly db: Db) {}

  private static toUser(row: UserRow): User {
    return {
      id: row.id,
      displayName: row.display_name ?? undefined,
      status: row.status as User['status'],
      createdAt: row.created_at,
    };
  }

  private static toIdentity(row: IdentityRow): Identity {
    return {
      id: row.id,
      userId: row.user_id,
      provider: row.provider,
      subject: row.subject,
      createdAt: row.created_at,
    };
  }

  private static toEmail(row: EmailRow): EmailAddress {
    return {
      id: row.id,
      userId: row.user_id,
      email: row.email,
      verified: row.verified,
      createdAt: row.created_at,
    };
  }

  // Ключ advisory-блокировки Postgres (bigint) из строкового ключа: первые
  // 8 байт SHA-256 как знаковое 64-битное число. Коллизия лишь сериализует
  // два несвязанных входа — на корректность не влияет.
  static advisoryKey(key: string): string {
    const digest = createHash('sha256').update(key).digest();
    return digest.readBigInt64BE(0).toString();
  }

  // Транзакция + pg_advisory_xact_lock по каждому ключу (в отсортированном
  // порядке — без взаимных блокировок). Блокировки снимаются с COMMIT/ROLLBACK,
  // поэтому держатся ровно столько, сколько единица работы. Нарушение
  // уникальности (страховка на случай гонки мимо блокировок) — откат и
  // IdentityConflictError, вызывающий повторяет единицу работы целиком.
  async runAtomic<T>(
    lockKeys: string[],
    fn: (repo: IdentityRepository) => Promise<T>,
  ): Promise<T> {
    try {
      return await this.db.withTransaction(async (tx) => {
        for (const key of [...new Set(lockKeys)].sort()) {
          await tx.query('select pg_advisory_xact_lock($1::bigint)', [
            PgIdentityRepository.advisoryKey(key),
          ]);
        }
        return fn(new PgIdentityRepository(tx));
      });
    } catch (err) {
      if ((err as { code?: unknown }).code === '23505') throw new IdentityConflictError();
      throw err;
    }
  }

  async findUserById(id: string): Promise<User | null> {
    const { rows } = await this.db.query<UserRow>(
      'select id, display_name, status, created_at from users where id = $1',
      [id],
    );
    return rows[0] ? PgIdentityRepository.toUser(rows[0]) : null;
  }

  async findIdentity(provider: string, subject: string): Promise<Identity | null> {
    const { rows } = await this.db.query<IdentityRow>(
      'select id, user_id, provider, subject, created_at from identities where provider = $1 and subject = $2',
      [provider, subject],
    );
    return rows[0] ? PgIdentityRepository.toIdentity(rows[0]) : null;
  }

  async findUserByVerifiedEmail(email: string): Promise<User | null> {
    const normalized = normalizeEmail(email);
    const { rows } = await this.db.query<UserRow>(
      `select u.id, u.display_name, u.status, u.created_at
         from email_addresses e
         join users u on u.id = e.user_id
        where e.email = $1 and e.verified = true`,
      [normalized],
    );
    return rows[0] ? PgIdentityRepository.toUser(rows[0]) : null;
  }

  async createUser(data: { displayName?: string }): Promise<User> {
    const { rows } = await this.db.query<UserRow>(
      `insert into users (id, display_name, status, created_at)
       values ($1, $2, $3, $4)
       returning id, display_name, status, created_at`,
      [randomUUID(), data.displayName ?? null, 'active', new Date()],
    );
    return PgIdentityRepository.toUser(rows[0]!);
  }

  async addIdentity(data: {
    userId: string;
    provider: string;
    subject: string;
  }): Promise<Identity> {
    const { rows } = await this.db.query<IdentityRow>(
      `insert into identities (id, user_id, provider, subject, created_at)
       values ($1, $2, $3, $4, $5)
       returning id, user_id, provider, subject, created_at`,
      [randomUUID(), data.userId, data.provider, data.subject, new Date()],
    );
    return PgIdentityRepository.toIdentity(rows[0]!);
  }

  async addEmail(data: {
    userId: string;
    email: string;
    verified: boolean;
  }): Promise<EmailAddress> {
    // Конфликт partial-unique (второй verified владелец адреса) намеренно
    // пробрасывается наверх — контракт эксклюзивности подтверждённого email.
    const { rows } = await this.db.query<EmailRow>(
      `insert into email_addresses (id, user_id, email, verified, created_at)
       values ($1, $2, $3, $4, $5)
       returning id, user_id, email, verified, created_at`,
      [randomUUID(), data.userId, normalizeEmail(data.email), data.verified, new Date()],
    );
    return PgIdentityRepository.toEmail(rows[0]!);
  }

  async findEmail(userId: string, email: string): Promise<EmailAddress | null> {
    const { rows } = await this.db.query<EmailRow>(
      'select id, user_id, email, verified, created_at from email_addresses where user_id = $1 and email = $2',
      [userId, normalizeEmail(email)],
    );
    return rows[0] ? PgIdentityRepository.toEmail(rows[0]) : null;
  }

  async findEmailsForUser(userId: string): Promise<EmailAddress[]> {
    const { rows } = await this.db.query<EmailRow>(
      'select id, user_id, email, verified, created_at from email_addresses where user_id = $1',
      [userId],
    );
    return rows.map((r) => PgIdentityRepository.toEmail(r));
  }

  async markEmailVerified(emailId: string): Promise<void> {
    await this.db.query('update email_addresses set verified = true where id = $1', [
      emailId,
    ]);
  }
}
