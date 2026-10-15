import { describe, it, expect } from 'vitest';
import { FakeMailer } from '../../../src/adapters/mail/fake-mailer.js';

describe('FakeMailer', () => {
  it('копит отправленные письма', async () => {
    const mailer = new FakeMailer();
    await mailer.send({ to: 'a@b.com', subject: 'Привет', text: 'тело' });
    expect(mailer.sent).toHaveLength(1);
    expect(mailer.sent[0]).toEqual({ to: 'a@b.com', subject: 'Привет', text: 'тело' });
  });

  it('last возвращает последнее письмо, null если пусто', async () => {
    const mailer = new FakeMailer();
    expect(mailer.last).toBeNull();
    await mailer.send({ to: 'x@y.com', subject: 's', text: 't' });
    expect(mailer.last?.to).toBe('x@y.com');
  });
});
