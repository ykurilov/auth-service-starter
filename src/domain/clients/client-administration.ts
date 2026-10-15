import { applyClientPatch, type Client, type ClientPatch } from './client.js';
import { ClientValidationError, assertProvidersAllowedForType } from './client-validation.js';
import type { ClientLock } from './client-lock.js';

export type ClientUpdateResult =
  | { status: 'updated'; client: Client }
  | { status: 'not_found' }
  | { status: 'invalid'; detail: string };

// Изменение и удаление клиента Admin API. Всё решение — проверка итогового
// состояния, запись и отзыв того, что выдано по прежним правилам, — под
// исключительной блокировкой клиента.
export class ClientAdministration {
  constructor(private readonly lock: ClientLock) {}

  async update(id: string, patch: ClientPatch): Promise<ClientUpdateResult> {
    return this.lock.exclusive(id, async (scope) => {
      const existing = scope.client;
      if (!existing) return { status: 'not_found' };
      const next = applyClientPatch(existing, patch);
      try {
        assertProvidersAllowedForType(next.type, next.allowedProviders);
      } catch (err) {
        if (err instanceof ClientValidationError) return { status: 'invalid', detail: err.message };
        throw err;
      }
      await scope.registry.update(id, patch);
      // Смена типа меняет правила входа (согласие пользователя): ничего, выданного
      // по прежним, не остаётся. Смена провайдеров гасит сессии тех, кто больше
      // не разрешён; их коды отклонит обмен: он сверяет провайдера под той же
      // блокировкой.
      if (next.type !== existing.type) {
        await scope.sessions.revokeForClient(id);
        await scope.invalidateCodes();
      } else if (patch.allowedProviders !== undefined) {
        await scope.sessions.revokeForClient(id, next.allowedProviders);
      }
      return { status: 'updated', client: (await scope.registry.findClient(id)) ?? next };
    });
  }

  // false — клиента не было.
  async remove(id: string): Promise<boolean> {
    return this.lock.exclusive(id, async (scope) => {
      if (!scope.client) return false;
      await scope.registry.delete(id);
      await scope.invalidateCodes();
      await scope.sessions.revokeForClient(id);
      return true;
    });
  }
}
