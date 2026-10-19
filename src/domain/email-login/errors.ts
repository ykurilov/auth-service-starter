import { MailDeliveryError } from '../../ports/mailer.js';

// Единая ошибка на «неверный логин/пароль или нет такого» — наружу не раскрываем, существует ли email.
export class InvalidCredentialsError extends Error {
  constructor() {
    super('неверные учётные данные');
    this.name = 'InvalidCredentialsError';
  }
}

// Адрес почты не прошёл строгую проверку (parseEmailAddress).
export class InvalidEmailError extends Error {
  constructor() {
    super('некорректный адрес почты');
    this.name = 'InvalidEmailError';
  }
}

// Письмо первого шага не подтвердилось (ошибка или таймаут провайдера), но
// попытка уже создана: письмо могло всё же дойти. Ошибка несёт handle попытки,
// чтобы браузер остался на экране кода — запоздавший код подойдёт. handle и
// адрес — не для журнала: поле неперечислимое, его не выведет и сериализатор,
// который обходит поля ошибки.
export class UnconfirmedCodeDeliveryError extends MailDeliveryError {
  declare readonly challenge: { handle: string; email: string };

  constructor(challenge: { handle: string; email: string }, cause: MailDeliveryError) {
    super(cause.message);
    this.message = cause.message;
    this.name = 'UnconfirmedCodeDeliveryError';
    Object.defineProperty(this, 'challenge', { value: challenge, enumerable: false });
  }
}

// Попытка начата у другой регистрации клиента (приложение удалили и создали
// заново с тем же id) или до миграции 0014: продолжать её нельзя.
export class ChallengeClientChangedError extends Error {
  constructor() {
    super('попытка входа начата у другой регистрации клиента');
    this.name = 'ChallengeClientChangedError';
  }
}
