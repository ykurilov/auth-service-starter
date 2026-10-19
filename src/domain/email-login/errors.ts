import { MailDeliveryError } from '../../ports/mailer.js';

// Единая ошибка на «неверный логин/пароль или нет такого» — наружу не раскрываем, существует ли email.
export class InvalidCredentialsError extends Error {
  constructor() {
    super('неверные учётные данные');
    this.name = 'InvalidCredentialsError';
  }
}

export class EmailAlreadyRegisteredError extends Error {
  constructor(email: string) {
    super(`email уже зарегистрирован: ${email}`);
    this.name = 'EmailAlreadyRegisteredError';
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
// чтобы браузер остался на экране кода — запоздавший код подойдёт.
export class UnconfirmedCodeDeliveryError extends MailDeliveryError {
  constructor(readonly challenge: { handle: string; email: string }, cause: MailDeliveryError) {
    super(cause.message);
    this.name = 'UnconfirmedCodeDeliveryError';
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
