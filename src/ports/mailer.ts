// Тип письма — безопасная метка для журнала: тема и тело содержат код.
export type EmailKind = 'login_code' | 'google_link_code';

export interface OutgoingEmail {
  to: string;
  subject: string;
  text: string;
  html?: string;
  kind?: EmailKind;
}

export interface Mailer {
  send(email: OutgoingEmail): Promise<void>;
}

// Исход неудачной отправки. rejected — провайдер ответил отказом: письма
// точно не будет. unconfirmed — ответа нет (таймаут, обрыв): письмо могло уйти.
export type MailDeliveryOutcome = 'rejected' | 'unconfirmed';

// Письмо не ушло: провайдер ответил ошибкой или не ответил вовремя.
// Обработчик показывает пользователю понятную страницу вместо 500.
export class MailDeliveryError extends Error {
  constructor(reason: string, readonly outcome: MailDeliveryOutcome = 'unconfirmed') {
    super(`письмо не отправлено: ${reason}`);
    this.name = 'MailDeliveryError';
  }
}
