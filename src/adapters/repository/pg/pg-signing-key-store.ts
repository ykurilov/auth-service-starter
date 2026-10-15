import type { Db } from '../../db/pool.js';
import type {
  SigningKeyStatus,
  SigningKeyStore,
  StoredSigningKey,
} from '../../../domain/tokens/signing-key-store.js';

// Строка signing_keys в snake_case; времена — timestamptz (Date).
interface SigningKeyRow {
  kid: string;
  private_pem: string;
  public_pem: string;
  alg: string;
  status: string;
  created_at: Date;
  retired_at: Date | null;
  revoked_at: Date | null;
}

const SELECT_COLUMNS =
  'kid, private_pem, public_pem, alg, status, created_at, retired_at, revoked_at';

// Postgres-реализация SigningKeyStore. Контракт совпадает с in-memory эталоном.
// rotate атомарен (одна транзакция): снимает все active, затем вставляет новый.
// Единственность active страхуется partial-unique индексом миграции 0002.
export class PgSigningKeyStore implements SigningKeyStore {
  constructor(private readonly db: Db) {}

  private static toRecord(row: SigningKeyRow): StoredSigningKey {
    return {
      kid: row.kid,
      privatePem: row.private_pem,
      publicPem: row.public_pem,
      alg: row.alg,
      status: row.status as SigningKeyStatus,
      createdAt: row.created_at,
      retiredAt: row.retired_at ?? null,
      revokedAt: row.revoked_at ?? null,
    };
  }

  private static async insert(db: Db, key: StoredSigningKey): Promise<void> {
    await db.query(
      `insert into signing_keys
         (kid, private_pem, public_pem, alg, status, created_at, retired_at, revoked_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        key.kid,
        key.privatePem,
        key.publicPem,
        key.alg,
        key.status,
        key.createdAt,
        key.retiredAt,
        key.revokedAt,
      ],
    );
  }

  async listAll(): Promise<StoredSigningKey[]> {
    const { rows } = await this.db.query<SigningKeyRow>(
      `select ${SELECT_COLUMNS} from signing_keys`,
    );
    return rows.map(PgSigningKeyStore.toRecord);
  }

  async getActive(): Promise<StoredSigningKey | null> {
    const { rows } = await this.db.query<SigningKeyRow>(
      `select ${SELECT_COLUMNS} from signing_keys where status = 'active' limit 1`,
    );
    return rows[0] ? PgSigningKeyStore.toRecord(rows[0]) : null;
  }

  async insertActive(key: StoredSigningKey): Promise<void> {
    await PgSigningKeyStore.insert(this.db, key);
  }

  async ensureActive(key: StoredSigningKey): Promise<StoredSigningKey> {
    try {
      await PgSigningKeyStore.insert(this.db, key);
    } catch (err) {
      // Гонка: другой инстанс уже вставил active — partial-unique отверг наш insert.
      // Перечитываем фактический active и уступаем ему. Если active нет, ошибка была
      // не про гонку (например, сбой БД) — пробрасываем её.
      const active = await this.getActive();
      if (!active) throw err;
      return active;
    }
    const active = await this.getActive();
    if (!active) {
      throw new Error('ensureActive: active-ключ не найден после вставки');
    }
    return active;
  }

  async rotate(newActive: StoredSigningKey, at: Date): Promise<void> {
    await this.db.withTransaction(async (tx) => {
      await tx.query(
        `update signing_keys set status = 'retired', retired_at = $1 where status = 'active'`,
        [at],
      );
      await PgSigningKeyStore.insert(tx, newActive);
    });
  }

  async revoke(kid: string, at: Date): Promise<void> {
    await this.db.query(
      `update signing_keys set revoked_at = $1 where kid = $2`,
      [at, kid],
    );
  }
}
