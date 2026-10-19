import { describe, it, expect, vi } from 'vitest';
import pino from 'pino';
import { ResendMailer, type ResendClientLike } from '../../../src/adapters/mail/resend-mailer.js';
import { MailDeliveryError } from '../../../src/ports/mailer.js';

// Фейковый resend-клиент: без сети, записывает переданный payload и возвращает
// заранее заданный результат.
function fakeClient(
  result: Awaited<ReturnType<ResendClientLike['emails']['send']>>,
): { client: ResendClientLike; calls: Parameters<ResendClientLike['emails']['send']>[0][] } {
  const calls: Parameters<ResendClientLike['emails']['send']>[0][] = [];
  return {
    calls,
    client: {
      emails: {
        async send(payload) {
          calls.push(payload);
          return result;
        },
      },
    },
  };
}

const logger = pino({ level: 'silent' });

describe('ResendMailer', () => {
  it('успешная отправка: не бросает и передаёт правильный payload', async () => {
    const { client, calls } = fakeClient({ data: { id: 'abc' }, error: null });
    const mailer = new ResendMailer(client, 'Auth Service <noreply@example.com>', logger);

    await mailer.send({
      to: 'user@example.com',
      subject: 'Код входа',
      text: 'Ваш код: 123456',
      html: '<b>123456</b>',
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({
      from: 'Auth Service <noreply@example.com>',
      to: 'user@example.com',
      subject: 'Код входа',
      text: 'Ваш код: 123456',
      html: '<b>123456</b>',
    });
  });

  it('ошибка провайдера: бросает Error с сообщением', async () => {
    const { client } = fakeClient({ data: null, error: { message: 'boom', name: 'x' } });
    const mailer = new ResendMailer(client, 'noreply@example.com', logger);

    await expect(
      mailer.send({ to: 'user@example.com', subject: 'Код', text: 'секрет 654321' }),
    ).rejects.toThrow(/boom/);
  });

  it('при ошибке не логирует тело письма (секрет не утекает)', async () => {
    const { client } = fakeClient({ data: null, error: { message: 'boom', name: 'x' } });
    const errorSpy = vi.fn();
    const spyLogger = { info: vi.fn(), error: errorSpy } as unknown as import('pino').Logger;
    const mailer = new ResendMailer(client, 'noreply@example.com', spyLogger);

    await expect(
      mailer.send({ to: 'user@example.com', subject: 'Код', text: 'секрет 654321' }),
    ).rejects.toThrow();

    expect(errorSpy).toHaveBeenCalledTimes(1);
    const logged = JSON.stringify(errorSpy.mock.calls[0]);
    expect(logged).not.toContain('654321');
  });
});

describe('ResendMailer: таймаут отправки (R15)', () => {
  it('Resend не отвечает → через 10 секунд MailDeliveryError, запрос получает signal', async () => {
    vi.useFakeTimers();
    try {
      let signal: AbortSignal | undefined;
      const client: ResendClientLike = {
        emails: {
          send: (_payload, options) => {
            signal = options?.signal;
            return new Promise(() => {});
          },
        },
      };
      const mailer = new ResendMailer(client, 'noreply@example.com', logger);
      const sending = mailer.send({ to: 'user@example.com', subject: 'Код', text: 'x' });
      const settled = vi.fn();
      sending.then(settled, settled);
      await vi.advanceTimersByTimeAsync(9_999);
      expect(settled).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      await expect(sending).rejects.toBeInstanceOf(MailDeliveryError);
      expect(signal).toBeInstanceOf(AbortSignal);
    } finally {
      vi.useRealTimers();
    }
  });

  it('ошибка провайдера тоже MailDeliveryError, и это окончательный отказ (P3-7)', async () => {
    const { client } = fakeClient({ data: null, error: { message: 'boom', name: 'x' } });
    const mailer = new ResendMailer(client, 'noreply@example.com', logger);
    const err = await mailer.send({ to: 'u@example.com', subject: 'Код', text: 'x' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MailDeliveryError);
    expect((err as MailDeliveryError).outcome).toBe('rejected');
  });

  it('сбой запроса без ответа провайдера — исход неизвестен (P3-7)', async () => {
    const client: ResendClientLike = { emails: { send: async () => { throw new Error('socket hang up'); } } };
    const mailer = new ResendMailer(client, 'noreply@example.com', logger);
    const err = await mailer.send({ to: 'u@example.com', subject: 'Код', text: 'x' }).catch((e: unknown) => e);
    expect((err as MailDeliveryError).outcome).toBe('unconfirmed');
  });
});

describe('ResendMailer: адрес из ответа провайдера (круг 6)', () => {
  const providerMessage =
    'You can only send testing emails to your own email address (owner@audit.example). To send to user@example.com, verify a domain.';

  it('не пишет адреса из текста отказа в журнал, но сохраняет смысл отказа', async () => {
    const { client } = fakeClient({ data: null, error: { message: providerMessage, name: 'validation_error' } });
    const errorSpy = vi.fn();
    const spyLogger = { info: vi.fn(), error: errorSpy } as unknown as import('pino').Logger;
    const mailer = new ResendMailer(client, 'noreply@example.com', spyLogger);

    await mailer.send({ to: 'user@example.com', subject: 'Код', text: 'x' }).catch(() => undefined);

    const logged = JSON.stringify(errorSpy.mock.calls);
    expect(logged).not.toContain('owner@audit.example');
    expect(logged).not.toContain('user@example.com');
    expect(logged).toContain('You can only send testing emails');
    expect(logged).toContain('validation_error');
  });

  it('не уносит адреса в текст ошибки', async () => {
    const { client } = fakeClient({ data: null, error: { message: providerMessage, name: 'validation_error' } });
    const mailer = new ResendMailer(client, 'noreply@example.com', logger);

    const err = (await mailer.send({ to: 'user@example.com', subject: 'Код', text: 'x' }).catch((e: unknown) => e)) as Error;

    expect(err).toBeInstanceOf(MailDeliveryError);
    expect(`${err.message}\n${err.stack ?? ''}`).not.toMatch(/owner@audit\.example|user@example\.com/);
  });
});
