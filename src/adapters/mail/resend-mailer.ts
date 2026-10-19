import { Resend } from 'resend';
import type { Logger } from 'pino';
import { MailDeliveryError, type Mailer, type OutgoingEmail } from '../../ports/mailer.js';
import { emailLogFields } from './email-log-fields.js';

// Минимальный интерфейс того, что нам нужно от resend-клиента — позволяет
// подменить его в тестах фейком без реальной сети.
export interface ResendClientLike {
  emails: {
    send(payload: {
      from: string;
      to: string;
      subject: string;
      html?: string;
      text: string;
    }, options?: { signal?: AbortSignal }): Promise<{
      data: { id: string } | null;
      error: { message: string; name: string } | null;
    }>;
  };
}

// Сколько ждём ответа Resend. Пользователь в это время смотрит на форму:
// дольше — уже не «медленно», а «сломалось».
export const RESEND_TIMEOUT_MS = 10_000;

// Боевой адаптер Mailer поверх Resend. Журнал получает только id письма у
// провайдера, тип письма и хеш адреса; при провале — ещё причину ошибки. Тема
// и тело (в них код входа) и открытый адрес в журнал не попадают.
// Любой провал — MailDeliveryError: ответ с ошибкой — окончательный отказ
// (rejected), нет ответа за RESEND_TIMEOUT_MS или обрыв запроса — исход
// неизвестен (unconfirmed). Таймер страхует и клиента, который не слушает signal.
export class ResendMailer implements Mailer {
  constructor(
    private readonly client: ResendClientLike,
    private readonly from: string, // уже собранная строка "Name <email>" или "email"
    private readonly logger: Logger,
    private readonly timeoutMs = RESEND_TIMEOUT_MS,
  ) {}

  async send(email: OutgoingEmail): Promise<void> {
    const abort = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    const timedOut = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        abort.abort();
        reject(new MailDeliveryError(`нет ответа Resend за ${this.timeoutMs} мс`));
      }, this.timeoutMs);
    });
    let result: Awaited<ReturnType<ResendClientLike['emails']['send']>>;
    try {
      result = await Promise.race([
        this.client.emails.send(
          { from: this.from, to: email.to, subject: email.subject, html: email.html, text: email.text },
          { signal: abort.signal },
        ),
        timedOut,
      ]);
    } catch (err) {
      this.logger.error({ provider: 'resend', ...emailLogFields(email), err }, 'ошибка отправки письма');
      throw err instanceof MailDeliveryError ? err : new MailDeliveryError('сбой запроса к Resend');
    } finally {
      clearTimeout(timer);
    }
    if (result.error) {
      const reason = withoutEmailAddresses(result.error.message);
      this.logger.error(
        { provider: 'resend', ...emailLogFields(email), error: reason, name: result.error.name },
        'ошибка отправки письма',
      );
      throw new MailDeliveryError(`Resend send failed: ${reason}`, 'rejected');
    }
    this.logger.info(
      { provider: 'resend', emailId: result.data?.id, ...emailLogFields(email) },
      'письмо отправлено (resend)',
    );
  }
}

// Фабрика для боевого пути: собирает реального клиента и строку from.
export function createResendMailer(opts: {
  apiKey: string;
  fromEmail: string;
  fromName?: string;
  logger: Logger;
}): Mailer {
  const from = opts.fromName ? `${opts.fromName} <${opts.fromEmail}>` : opts.fromEmail;
  return new ResendMailer(
    new Resend(opts.apiKey) as unknown as ResendClientLike,
    from,
    opts.logger,
  );
}

// Провайдер вписывает адреса в текст отказа («only send testing emails to
// owner@…»). Смысл отказа нужен для разбора, адреса в журнал попадать не должны.
function withoutEmailAddresses(message: string): string {
  return message.replace(/[^\s<>()"',;:]+@[^\s<>()"',;:]+/g, '[адрес]');
}
