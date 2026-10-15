export interface OutgoingEmail {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

export interface Mailer {
  send(email: OutgoingEmail): Promise<void>;
}

// Письмо не ушло: провайдер ответил ошибкой или не ответил вовремя.
// Обработчик показывает пользователю понятную страницу вместо 500.
export class MailDeliveryError extends Error {
  constructor(reason: string) {
    super(`письмо не отправлено: ${reason}`);
    this.name = 'MailDeliveryError';
  }
}
