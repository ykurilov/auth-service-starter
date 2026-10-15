import { describe, it, expect, vi } from 'vitest';
import pino from 'pino';
import { ResendMailer, type ResendClientLike } from '../../../src/adapters/mail/resend-mailer.js';

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
