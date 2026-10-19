import { randomBytes } from 'node:crypto';
import type { AuthSnapshot } from '../login/authorization-code.js';
import type { SessionStore } from '../sessions/session.js';

export interface SsoSession {
  id: string;
  userId: string;
  // auth.loginId — вход, которым начата сессия: коды, выданные этим входом
  // и тихими входами через эту SSO-сессию, несут тот же loginId.
  auth: AuthSnapshot;
  tokenHash: string;
  // Цепочка SSO-сессий одного браузера: новая сессия, сменившая прежнюю
  // sso-cookie, наследует её цепочку. Сессии приложений, выданные через
  // цепочку, помнят её (Session.ssoChainId) и гаснут при смене аккаунта
  // в браузере и при выходе.
  chainId: string;
  createdAt: Date;
  lastUsedAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}

// Привязка браузера к цепочке: долгоживущая cookie с секретом (здесь — его
// хеш). Права входа не даёт: по ней выход и смена аккаунта находят цепочку
// браузера, когда SSO-cookie уже истекла, а сессии приложений цепочки ещё
// живы. У цепочки их может быть несколько, каждая со своим сроком: вкладки,
// одновременно получившие привязку, получают разные секреты, а браузер
// сохраняет тот, чей ответ пришёл последним.
export interface BrowserBinding {
  chainId: string;
  tokenHash: string;
  createdAt: Date;
  expiresAt: Date;
}

// Срок cookie привязки с последнего захода браузера на страницы входа. Сессия
// приложения не продлевается дальше привязки своей цепочки (browserDeadline),
// поэтому, пока она жива, браузер может её найти. Меньше предела браузеров
// для cookie (Chrome — 400 дней).
export const BROWSER_BINDING_TTL_SECONDS = 365 * 24 * 3600;

// Больше привязок у цепочки не бывает: самые давние по сроку удаляются.
// Новая привязка появляется, только когда браузер не прислал действующую,
// так что у живого браузера их одна-две; предел не даёт клиенту, не
// хранящему cookie, копить строки на год вперёд.
export const MAX_BINDINGS_PER_CHAIN = 10;

export interface SsoSessionStore {
  save(session: SsoSession): Promise<void>;
  // Находит сессию и после отзыва или истечения: выход повторяем по старой cookie.
  findByHash(tokenHash: string): Promise<SsoSession | null>;
  // Сессия, начатая входом loginId (auth.loginId), в любом состоянии. У
  // каждого входа своя SSO-сессия.
  findByLogin(loginId: string): Promise<SsoSession | null>;
  // Последняя по времени создания сессия цепочки (её cookie сейчас у браузера).
  findLatestInChain(chainId: string): Promise<SsoSession | null>;
  // Блокировка цепочки до конца текущей транзакции (в БД — advisory-блокировка
  // по chainId). Вход, выход и обмен кода, выданного через цепочку, меняют и
  // проверяют её только под этой блокировкой, по очереди, и каждый видит
  // зафиксированное предыдущим. Вне транзакции смысла не имеет. В памяти — очередь
  // по chainId до конца atomically (или блокировки клиента).
  lockChain(chainId: string): Promise<void>;
  // Блокировки нескольких цепочек в едином для всего сервиса порядке (в БД —
  // по возрастанию ключа advisory-блокировки, в памяти — по chainId).
  // Операция, которой нужна не одна цепочка (cookie браузера относятся к
  // разным), берёт их одним вызовом до первого изменения строк: иначе две
  // такие операции с противоположными парами цепочек ждут друг друга.
  lockChains(chainIds: readonly string[]): Promise<void>;
  // Есть ли в цепочке неотозванная сессия этого пользователя. В БД найденные
  // строки удерживаются (FOR SHARE) до конца транзакции: выход и смена
  // аккаунта, которые их отзывают, ждут её фиксации.
  holdSignedIn(chainId: string, userId: string): Promise<boolean>;
  touch(id: string, lastUsedAt: Date, expiresAt: Date): Promise<void>;
  revoke(id: string, at: Date): Promise<void>;
  // Отзывает все ещё живые сессии цепочки.
  revokeChain(chainId: string, at: Date): Promise<void>;
  // Привязка браузера по хешу её секрета, в любом состоянии.
  findBinding(tokenHash: string): Promise<BrowserBinding | null>;
  // Добавляет привязку цепочки, не трогая прочие, кроме самых давних сверх
  // MAX_BINDINGS_PER_CHAIN.
  addBinding(binding: BrowserBinding): Promise<void>;
  // Новый срок привязки. false — её уже нет (удалена выходом или сменой аккаунта).
  renewBinding(tokenHash: string, expiresAt: Date): Promise<boolean>;
  deleteBinding(tokenHash: string): Promise<void>;
  // Удаляет все привязки цепочки.
  deleteChainBindings(chainId: string): Promise<void>;
  // До какого момента браузер цепочки может её найти: позднейший срок её
  // привязок и её SSO-сессий (cookie живут столько же). null — ни того ни
  // другого нет.
  browserDeadline(chainId: string): Promise<Date | null>;
  // Удаляет записи с expires_at < before ИЛИ (отозвана И revoked_at < before),
  // и привязки с expires_at < before. Возвращает число удалённых.
  deleteExpired(before: Date): Promise<number>;
}

export interface SsoStoreSet {
  sso: SsoSessionStore;
  sessions: SessionStore;
}

// Хранилища SSO-сессий и сессий приложений. atomically — изменения обоих одной
// транзакцией (в памяти — просто вызов): смена аккаунта и выход не оставляют
// SSO-сессию отозванной, а сессии приложений живыми.
export interface SsoStores extends SsoStoreSet {
  atomically<T>(fn: (stores: SsoStoreSet) => Promise<T>): Promise<T>;
}

export function generateSsoToken(): string {
  return randomBytes(32).toString('base64url');
}
