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
