import type { Db } from '../../db/pool.js';
import type {
  GoogleNonceRecord,
  GoogleNonceStore,
} from '../../../domain/google-login/google-nonce.js';

// Nonce Google в Postgres: общий для всех экземпляров и переживает перезапуск.
// Гашение — одиночный UPDATE ... WHERE consumed_at is null RETURNING (CAS).
export class PgGoogleNonceStore implements GoogleNonceStore {
  constructor(private readonly db: Db) {}

  async save(r: GoogleNonceRecord): Promise<void> {
    await this.db.query(
      `insert into google_login_nonces (nonce_hash, binding_hash, client_id, created_at, expires_at, consumed_at)
       values ($1, $2, $3, $4, $5, null)`,
      [r.nonceHash, r.bindingHash, r.clientId, r.createdAt, r.expiresAt],
    );
  }

  async consume(nonceHash: string, bindingHash: string, clientId: string, now: Date): Promise<boolean> {
    const { rowCount } = await this.db.query(
      `update google_login_nonces set consumed_at = $4
        where nonce_hash = $1 and binding_hash = $2 and client_id = $3
          and consumed_at is null and expires_at > $4
        returning nonce_hash`,
      [nonceHash, bindingHash, clientId, now],
    );
    return rowCount === 1;
  }

  async deleteExpired(before: Date): Promise<number> {
    const { rowCount } = await this.db.query(
      'delete from google_login_nonces where expires_at < $1',
      [before],
    );
    return rowCount;
  }
}
