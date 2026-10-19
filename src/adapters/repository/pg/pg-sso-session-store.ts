import type { Db } from '../../db/pool.js';
import {
  MAX_BINDINGS_PER_CHAIN,
  type BrowserBinding,
  type SsoSession,
  type SsoSessionStore,
  type SsoStores,
} from '../../../domain/sso/sso-session.js';
import { PgSessionStore } from './pg-session-store.js';
import type { AuthSnapshot } from '../../../domain/login/authorization-code.js';
import { PgIdentityRepository } from './pg-identity-repository.js';

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

interface BindingRow { chain_id: string; token_hash: string; created_at: Date; expires_at: Date }

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

  private static toBinding(row: BindingRow): BrowserBinding {
    return { chainId: row.chain_id, tokenHash: row.token_hash, createdAt: row.created_at, expiresAt: row.expires_at };
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

  // Транзакционная advisory-блокировка: снимается с COMMIT/ROLLBACK. Ключ —
  // из chainId с префиксом; коллизия лишь сериализует несвязанные цепочки.
  async lockChain(chainId: string): Promise<void> {
    await this.db.query('select pg_advisory_xact_lock($1::bigint)', [PgSsoSessionStore.chainKey(chainId)]);
  }

  // По возрастанию ключа, а не chainId: у двух цепочек ключ может совпасть, и
  // порядок по chainId тогда не был бы порядком самих блокировок. Совпавший
  // ключ берётся один раз.
  async lockChains(chainIds: readonly string[]): Promise<void> {
    const byKey = new Map(chainIds.map((id) => [BigInt(PgSsoSessionStore.chainKey(id)), id]));
    for (const key of [...byKey.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
      await this.lockChain(byKey.get(key)!);
    }
  }

  private static chainKey(chainId: string): string {
    return PgIdentityRepository.advisoryKey(`sso-chain:${chainId}`);
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

  // Привязки — в sso_chain_bindings; в sso_browser_bindings (одна на цепочку)
  // их пишет копия прежней версии во время раскатки: их тоже находим, а при
  // продлении переносим сюда.
  async findBinding(tokenHash: string): Promise<BrowserBinding | null> {
    for (const table of ['sso_chain_bindings', 'sso_browser_bindings']) {
      const { rows } = await this.db.query<BindingRow>(
        `select chain_id, token_hash, created_at, expires_at from ${table} where token_hash = $1`,
        [tokenHash],
      );
      if (rows[0]) return PgSsoSessionStore.toBinding(rows[0]);
    }
    return null;
  }

  async addBinding(binding: BrowserBinding): Promise<void> {
    await this.db.query(
      'insert into sso_chain_bindings (token_hash, chain_id, created_at, expires_at) values ($1, $2, $3, $4)',
      [binding.tokenHash, binding.chainId, binding.createdAt, binding.expiresAt],
    );
    // Срок первой лишней привязки по убыванию сроков: она и более давние уходят.
    const { rows } = await this.db.query<{ expires_at: Date }>(
      `select expires_at from sso_chain_bindings where chain_id = $1
        order by expires_at desc offset $2 limit 1`,
      [binding.chainId, MAX_BINDINGS_PER_CHAIN],
    );
    if (rows[0]) {
      await this.db.query(
        'delete from sso_chain_bindings where chain_id = $1 and expires_at <= $2 and token_hash <> $3',
        [binding.chainId, rows[0].expires_at, binding.tokenHash],
      );
    }
  }

  async renewBinding(tokenHash: string, expiresAt: Date): Promise<boolean> {
    const renewed = await this.db.query(
      'update sso_chain_bindings set expires_at = $2 where token_hash = $1',
      [tokenHash, expiresAt],
    );
    if (renewed.rowCount > 0) return true;
    const moved = await this.db.query(
      `insert into sso_chain_bindings (token_hash, chain_id, created_at, expires_at)
         select token_hash, chain_id, created_at, $2::timestamptz from sso_browser_bindings where token_hash = $1`,
      [tokenHash, expiresAt],
    );
    await this.db.query('delete from sso_browser_bindings where token_hash = $1', [tokenHash]);
    return moved.rowCount > 0;
  }

  async deleteBinding(tokenHash: string): Promise<void> {
    await this.db.query('delete from sso_chain_bindings where token_hash = $1', [tokenHash]);
    await this.db.query('delete from sso_browser_bindings where token_hash = $1', [tokenHash]);
  }

  async deleteChainBindings(chainId: string): Promise<void> {
    await this.db.query('delete from sso_chain_bindings where chain_id = $1', [chainId]);
    await this.db.query('delete from sso_browser_bindings where chain_id = $1', [chainId]);
  }

  // Простые запросы вместо greatest() с подзапросами: так понимает и pg-mem.
  async browserDeadline(chainId: string): Promise<Date | null> {
    const times: number[] = [];
    for (const table of ['sso_chain_bindings', 'sso_browser_bindings', 'sso_sessions']) {
      const { rows } = await this.db.query<{ expires_at: Date }>(
        `select expires_at from ${table} where chain_id = $1 order by expires_at desc limit 1`,
        [chainId],
      );
      times.push(...rows.map((r) => r.expires_at.getTime()));
    }
    return times.length > 0 ? new Date(Math.max(...times)) : null;
  }

  // `revoked_at < $1` уже подразумевает not null (NULL < x -> NULL -> false);
  // без явного `is not null` ещё и потому, что pg-mem теряет строки на этой
  // связке при индексе по колонке (см. PgSessionStore.deleteExpired).
  async deleteExpired(before: Date): Promise<number> {
    const { rowCount } = await this.db.query(
      'delete from sso_sessions where expires_at < $1 or revoked_at < $1',
      [before],
    );
    const bindings = await this.db.query('delete from sso_chain_bindings where expires_at < $1', [before]);
    const legacy = await this.db.query('delete from sso_browser_bindings where expires_at < $1', [before]);
    return rowCount + bindings.rowCount + legacy.rowCount;
  }
}
