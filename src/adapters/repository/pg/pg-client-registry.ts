import type { Db } from '../../db/pool.js';
import type { Client, ClientPatch, ClientRegistry } from '../../../domain/clients/client.js';

// Строка clients: массивы хранятся в jsonb-колонках, времена — timestamptz.
interface ClientRow {
  id: string;
  type: string;
  redirect_uris: unknown;
  allowed_providers: unknown;
  post_logout_redirect_uris: unknown;
}

// jsonb-массив приходит из драйвера уже распарсенным объектом (массивом).
// Нормализуем к string[] с фолбэком на пустой массив.
function toStringArray(value: unknown): string[] {
  return Array.isArray(value) ? (value as string[]) : [];
}

// Значение для jsonb-параметра. pg (и pg-mem) принимают JSON-строку для jsonb-колонки
// и читают её обратно как массив.
function jsonbParam(arr: string[]): string {
  return JSON.stringify(arr);
}

// Postgres-реализация ClientRegistry. Помимо интерфейсного findClient содержит
// методы для Admin API (list/create/update/delete/upsert) — интерфейс не расширяем.
export class PgClientRegistry implements ClientRegistry {
  constructor(private readonly db: Db) {}

  private static toClient(row: ClientRow): Client {
    const client: Client = {
      id: row.id,
      type: row.type as Client['type'],
      redirectUris: toStringArray(row.redirect_uris),
      allowedProviders: toStringArray(row.allowed_providers),
    };
    // Колонка nullable: отсутствующий список не превращаем в [].
    if (row.post_logout_redirect_uris != null) {
      client.postLogoutRedirectUris = toStringArray(row.post_logout_redirect_uris);
    }
    return client;
  }

  private static selectColumns =
    'id, type, redirect_uris, allowed_providers, post_logout_redirect_uris';

  async findClient(id: string): Promise<Client | null> {
    const { rows } = await this.db.query<ClientRow>(
      `select ${PgClientRegistry.selectColumns} from clients where id = $1`,
      [id],
    );
    return rows[0] ? PgClientRegistry.toClient(rows[0]) : null;
  }

  // Чтение с блокировкой строки до конца транзакции (вызывать внутри неё):
  // 'share' — обмен кода, 'update' — изменение и удаление клиента.
  async findClientLocked(id: string, mode: 'share' | 'update'): Promise<Client | null> {
    const { rows } = await this.db.query<ClientRow>(
      `select ${PgClientRegistry.selectColumns} from clients where id = $1 for ${mode === 'share' ? 'share' : 'update'}`,
      [id],
    );
    return rows[0] ? PgClientRegistry.toClient(rows[0]) : null;
  }

  async list(): Promise<Client[]> {
    const { rows } = await this.db.query<ClientRow>(
      `select ${PgClientRegistry.selectColumns} from clients`,
    );
    return rows.map((r) => PgClientRegistry.toClient(r));
  }

  async create(client: Client): Promise<void> {
    const now = new Date();
    await this.db.query(
      `insert into clients
         (id, type, redirect_uris, allowed_providers, post_logout_redirect_uris, created_at, updated_at)
       values ($1, $2, $3, $4, $5, $6, $6)`,
      [
        client.id,
        client.type,
        jsonbParam(client.redirectUris),
        jsonbParam(client.allowedProviders),
        client.postLogoutRedirectUris ? jsonbParam(client.postLogoutRedirectUris) : null,
        now,
      ],
    );
  }

  async upsert(client: Client): Promise<void> {
    const now = new Date();
    await this.db.query(
      `insert into clients
         (id, type, redirect_uris, allowed_providers, post_logout_redirect_uris, created_at, updated_at)
       values ($1, $2, $3, $4, $5, $6, $6)
       on conflict (id) do update set
         type = excluded.type,
         redirect_uris = excluded.redirect_uris,
         allowed_providers = excluded.allowed_providers,
         post_logout_redirect_uris = excluded.post_logout_redirect_uris,
         updated_at = excluded.updated_at`,
      [
        client.id,
        client.type,
        jsonbParam(client.redirectUris),
        jsonbParam(client.allowedProviders),
        client.postLogoutRedirectUris ? jsonbParam(client.postLogoutRedirectUris) : null,
        now,
      ],
    );
  }

  // Персистентная отметка предотвращает повторное создание удалённых клиентов.
  // INSERT блокирует конкурирующий bootstrap до COMMIT, все клиенты — в одной транзакции.
  async seedInitial(clients: Client[]): Promise<void> {
    await this.db.withTransaction(async (tx) => {
      const claimed = await tx.query(
        `insert into bootstrap_state (name) values ('initial-clients') on conflict (name) do nothing returning name`,
      );
      if (claimed.rowCount === 0) return;
      const registry = new PgClientRegistry(tx);
      for (const client of clients) await registry.seed(client);
    });
  }

  // Сидирование из конфига при старте: вставляет только недостающих клиентов,
  // не затирая правки существующих (сделанные через Admin API прямо в БД).
  async seed(client: Client): Promise<void> {
    const now = new Date();
    await this.db.query(
      `insert into clients
         (id, type, redirect_uris, allowed_providers, post_logout_redirect_uris, created_at, updated_at)
       values ($1, $2, $3, $4, $5, $6, $6)
       on conflict (id) do nothing`,
      [
        client.id,
        client.type,
        jsonbParam(client.redirectUris),
        jsonbParam(client.allowedProviders),
        client.postLogoutRedirectUris ? jsonbParam(client.postLogoutRedirectUris) : null,
        now,
      ],
    );
  }

  async update(id: string, patch: ClientPatch): Promise<void> {
    const sets: string[] = [];
    const params: unknown[] = [];
    // Белый список колонок: имена — из кода, значения — только через параметры.
    if (patch.type !== undefined) {
      params.push(patch.type);
      sets.push(`type = $${params.length}`);
    }
    if (patch.redirectUris !== undefined) {
      params.push(jsonbParam(patch.redirectUris));
      sets.push(`redirect_uris = $${params.length}`);
    }
    if (patch.allowedProviders !== undefined) {
      params.push(jsonbParam(patch.allowedProviders));
      sets.push(`allowed_providers = $${params.length}`);
    }
    if (patch.postLogoutRedirectUris !== undefined) {
      params.push(
        patch.postLogoutRedirectUris ? jsonbParam(patch.postLogoutRedirectUris) : null,
      );
      sets.push(`post_logout_redirect_uris = $${params.length}`);
    }

    params.push(new Date());
    sets.push(`updated_at = $${params.length}`);

    params.push(id);
    await this.db.query(
      `update clients set ${sets.join(', ')} where id = $${params.length}`,
      params,
    );
  }

  async delete(id: string): Promise<void> {
    await this.db.query('delete from clients where id = $1', [id]);
  }
}
