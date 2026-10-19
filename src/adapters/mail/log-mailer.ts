import type { Logger } from 'pino';
import type { Mailer, OutgoingEmail } from '../../ports/mailer.js';
import { emailLogFields } from './email-log-fields.js';

// Адаптер Mailer без почтового провайдера: письмо никуда не уходит. Журнал
// получает только безопасные поля — ни адреса, ни темы (в ней код), ни тела.
export class LogMailer implements Mailer {
  constructor(private readonly logger: Logger) {}

  async send(email: OutgoingEmail): Promise<void> {
    this.logger.info(emailLogFields(email), 'письмо не отправлено: почта не настроена (log-mailer)');
  }
}
