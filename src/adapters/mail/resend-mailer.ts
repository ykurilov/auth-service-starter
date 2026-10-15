import { Resend } from 'resend';
import type { Logger } from 'pino';
import { MailDeliveryError, type Mailer, type OutgoingEmail } from '../../ports/mailer.js';

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

// Боевой адаптер Mailer поверх Resend. Логирует только факт отправки и (при
// провале) причину ошибки — тело письма (в нём код входа) НЕ логируется.
// Любой провал (ошибка провайдера или нет ответа за RESEND_TIMEOUT_MS) —
// MailDeliveryError. Таймер страхует и клиента, который не слушает signal.
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
      this.logger.error({ provider: 'resend', err }, 'ошибка отправки письма');
      throw err instanceof MailDeliveryError ? err : new MailDeliveryError('сбой запроса к Resend');
    } finally {
      clearTimeout(timer);
    }
    if (result.error) {
      // Тело письма (код) НЕ логируем — только факт и причину ошибки.
      this.logger.error(
        { provider: 'resend', error: result.error.message, name: result.error.name },
        'ошибка отправки письма',
      );
      throw new MailDeliveryError(`Resend send failed: ${result.error.message}`);
    }
    this.logger.info(
      { provider: 'resend', to: email.to, subject: email.subject, emailId: result.data?.id },
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
