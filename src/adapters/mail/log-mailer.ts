import type { Logger } from 'pino';
import type { Mailer, OutgoingEmail } from '../../ports/mailer.js';

// Реальный (не тестовый) адаптер Mailer. Логирует только факт отправки:
// адрес и тему. Тело письма (в нём код входа) НЕ логируется — секрет не
// должен утекать в логи.
export class LogMailer implements Mailer {
  constructor(private readonly logger: Logger) {}

  async send(email: OutgoingEmail): Promise<void> {
    this.logger.info({ to: email.to, subject: email.subject }, 'письмо отправлено (log-mailer)');
  }
}
