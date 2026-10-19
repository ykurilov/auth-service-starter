import type { Db } from '../../db/pool.js';
import type { ClientLock, ClientScope, ClientWriteScope } from '../../../domain/clients/client-lock.js';
import { PgClientRegistry } from './pg-client-registry.js';

// Сервисы, собранные поверх Db транзакции (хранилища пишут в неё же).
export type ClientScopeServices = (tx: Db) => Pick<ClientScope, 'codes' | 'sessions' | 'sso'>;

// Блокировка клиента — блокировка его строки в clients: FOR SHARE у обменов
// кода, FOR UPDATE у изменения и удаления. Всё, что делает fn, идёт в той же
// транзакции и фиксируется вместе. Если клиента нет, строки для блокировки
// тоже нет: обмен всё равно отклонит код (он привязан к регистрации клиента).
export class PgClientLock implements ClientLock {
  constructor(
    private readonly db: Db,
    private readonly services: ClientScopeServices,
  ) {}

  shared<T>(clientId: string, fn: (scope: ClientScope) => Promise<T>): Promise<T> {
    return this.db.withTransaction(async (tx) => {
      const client = await new PgClientRegistry(tx).findClientLocked(clientId, 'share');
      return fn({ client, ...this.services(tx) });
    });
  }

  exclusive<T>(clientId: string, fn: (scope: ClientWriteScope) => Promise<T>): Promise<T> {
    return this.db.withTransaction(async (tx) => {
      const registry = new PgClientRegistry(tx);
      const client = await registry.findClientLocked(clientId, 'update');
      return fn({
        client,
        registry,
        ...this.services(tx),
        async invalidateCodes() {
          await tx.query(
            'update authorization_codes set consumed_at = now() where client_id = $1 and consumed_at is null',
            [clientId],
          );
        },
      });
    });
  }
}
