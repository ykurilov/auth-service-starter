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

export interface LoginChallengeRecord {
  id: string;
  handleHash: string;
  bindingHash: string;
  email: string; // нормализованный и прошедший parseEmailAddress
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
  // Атомарная замена кода (переотправка): новый hash и срок, resends + 1, только
  // если попытка жива, resends < maxResends и проверки ещё остались. Старый код
  // перестаёт действовать в тот же момент. attempts не сбрасывается.
  rotateCode(
    handleHash: string,
    bindingHash: string,
    codeHash: string,
    expiresAt: Date,
    now: Date,
  ): Promise<LoginChallengeRecord | null>;
  // CAS-гашение после верного кода: true — этот вызов погасил.
  consume(id: string, at: Date): Promise<boolean>;
  deleteExpired(before: Date): Promise<number>;
}
