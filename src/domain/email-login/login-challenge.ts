// Попытка входа по коду из письма. Её handle — случайный секрет, который знает
// только браузер, начавший вход (скрытое поле формы); в хранилище лежит его
// хеш. Попытка дополнительно привязана к браузеру хешем csrf-cookie
// (bindingHash). Код хранится хешем с солью handle: утечка таблицы не даёт
// перебрать 6 цифр офлайн. Лимит проверок и переотправок — на самой попытке,
// поэтому чужие ошибки (у постороннего свой handle) не тратят попытки владельца.

// Отложенная привязка внешней личности (вход через Google со сторонним адресом
// без доказанного владения): выполняется только после верного кода из письма.
export interface PendingLink {
  provider: string;
  subject: string;
  name?: string;
}

// Клиент, под которым начата попытка: id и регистрация из проверенного снимка.
export interface ChallengeClient {
  id: string;
  registrationId?: string;
}

export interface LoginChallengeRecord {
  id: string;
  handleHash: string;
  bindingHash: string;
  email: string; // нормализованный и прошедший parseEmailAddress
  // Клиент и его регистрация на старте попытки. null у clientId — попытка,
  // начатая до миграции 0014: клиента она не знает и не принимается никем.
  clientId: string | null;
  clientRegistrationId: string | null;
  codeHash: string;
  attempts: number;
  maxAttempts: number;
  resends: number;
  maxResends: number;
  link: PendingLink | null;
  createdAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
}

export interface LoginChallengeStore {
  create(record: LoginChallengeRecord): Promise<void>;
  // Живая (не погашенная, не истёкшая) попытка этого браузера.
  find(handleHash: string, bindingHash: string, now: Date): Promise<LoginChallengeRecord | null>;
  // Атомарно занимает одну проверку: attempts + 1, только если попытка жива и
  // attempts < maxAttempts. null — проверок не осталось (или попытки нет).
  // Возвращает запись ПОСЛЕ увеличения. SQL: UPDATE ... WHERE attempts < max RETURNING.
  claimAttempt(handleHash: string, bindingHash: string, now: Date): Promise<LoginChallengeRecord | null>;
  // Переотправка в три шага. reserveResend атомарно занимает слот (resends + 1,
  // только если попытка жива, resends < maxResends и проверки ещё остались) —
  // до отправки письма, поэтому параллельные запросы не превысят лимит. Код
  // пока прежний. SQL: UPDATE ... WHERE resends < max RETURNING.
  reserveResend(handleHash: string, bindingHash: string, now: Date): Promise<LoginChallengeRecord | null>;
  // Письмо ушло: новый hash и срок для живой попытки. Прежний код перестаёт
  // действовать в тот же момент. false — попытку погасили, пока шло письмо.
  replaceCode(id: string, codeHash: string, expiresAt: Date, now: Date): Promise<boolean>;
  // Письмо не ушло: слот возвращается, прежний код остаётся.
  releaseResend(id: string): Promise<void>;
  // CAS-гашение после верного кода: true — этот вызов погасил.
  consume(id: string, at: Date): Promise<boolean>;
  deleteExpired(before: Date): Promise<number>;
}
