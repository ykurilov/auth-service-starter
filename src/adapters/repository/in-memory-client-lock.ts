import type { ClientWriteStore } from '../../domain/clients/client.js';
import type { ClientLock, ClientScope, ClientWriteScope } from '../../domain/clients/client-lock.js';

// Блокировка клиента для режима без БД (один процесс): операции над одним
// клиентом идут строго по очереди, общие и исключительные — одинаково.
export class InMemoryClientLock implements ClientLock {
  private readonly queues = new Map<string, Promise<unknown>>();

  constructor(
    private readonly registry: ClientWriteStore,
    private readonly services: Pick<ClientScope, 'codes' | 'sessions' | 'sso'>,
    private readonly invalidateCodes: (clientId: string) => Promise<void>,
  ) {}

  shared<T>(clientId: string, fn: (scope: ClientScope) => Promise<T>): Promise<T> {
    return this.exclusive(clientId, fn);
  }

  exclusive<T>(clientId: string, fn: (scope: ClientWriteScope) => Promise<T>): Promise<T> {
    const run = async (): Promise<T> =>
      fn({
        client: await this.registry.findClient(clientId),
        registry: this.registry,
        ...this.services,
        invalidateCodes: () => this.invalidateCodes(clientId),
      });
    const result = (this.queues.get(clientId) ?? Promise.resolve()).then(run, run);
    const tail = result.catch(() => undefined);
    this.queues.set(clientId, tail);
    // Очередь клиента не копится в памяти: последний в ней убирает её за собой.
    void tail.then(() => {
      if (this.queues.get(clientId) === tail) this.queues.delete(clientId);
    });
    return result;
  }
}
