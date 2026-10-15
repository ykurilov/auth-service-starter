import type { Client, ClientWriteStore } from './client.js';
import type { AuthorizationCodeService } from '../login/authorization-code-service.js';
import type { SessionService } from '../sessions/session-service.js';

// Сервисы, которые работают под той же блокировкой клиента, что и снимок client:
// в Postgres — в одной транзакции с ним.
export interface ClientScope {
  // Клиент на момент взятия блокировки; null — такого клиента нет.
  client: Client | null;
  codes: AuthorizationCodeService;
  sessions: SessionService;
}

export interface ClientWriteScope extends ClientScope {
  registry: ClientWriteStore;
  // Гасит все непогашенные коды авторизации клиента.
  invalidateCodes(): Promise<void>;
}

// Блокировка регистрации клиента. Обмен кода на сессию идёт под общей
// блокировкой, изменение и удаление клиента — под исключительной. Поэтому
// изменение ждёт начатые обмены и видит созданные ими сессии, а обмен после
// изменения видит уже новую политику.
export interface ClientLock {
  shared<T>(clientId: string, fn: (scope: ClientScope) => Promise<T>): Promise<T>;
  exclusive<T>(clientId: string, fn: (scope: ClientWriteScope) => Promise<T>): Promise<T>;
}
