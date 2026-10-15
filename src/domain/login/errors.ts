export class InvalidClientError extends Error {
  constructor() {
    super('неизвестный client_id');
    this.name = 'InvalidClientError';
  }
}

export class InvalidRedirectUriError extends Error {
  constructor() {
    super('redirect_uri не разрешён');
    this.name = 'InvalidRedirectUriError';
  }
}

export class UnsupportedPkceError extends Error {
  constructor() {
    super('требуется code_challenge с методом S256');
    this.name = 'UnsupportedPkceError';
  }
}

export class ProviderNotAllowedError extends Error {
  constructor(provider: string) {
    super(`провайдер ${provider} не разрешён этому приложению`);
    this.name = 'ProviderNotAllowedError';
  }
}

// Единая ошибка на любой провал обмена кода — не раскрываем, какая именно проверка не прошла.
export class InvalidGrantError extends Error {
  constructor() {
    super('код авторизации недействителен');
    this.name = 'InvalidGrantError';
  }
}
