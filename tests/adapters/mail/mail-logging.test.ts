import { describe, it, expect } from 'vitest';
import { Writable } from 'node:stream';
import pino from 'pino';
import { ResendMailer, type ResendClientLike } from '../../../src/adapters/mail/resend-mailer.js';
import { LogMailer } from '../../../src/adapters/mail/log-mailer.js';
import { buildGoogleLinkCodeEmail, buildLoginCodeEmail } from '../../../src/adapters/mail/templates.js';
import { EmailCodeProvider } from '../../../src/domain/email-login/email-code-provider.js';
import { InMemoryLoginChallengeStore } from '../../../src/adapters/repository/in-memory-login-challenge-store.js';
import { sha256Hex } from '../../../src/domain/shared/hash.js';
import { buildServer } from '../../../src/adapters/http/server.js';
import { fakeClock } from '../../helpers/fake-clock.js';
import { makeTestDeps, authorizeForm, FORM_HEADERS, extractChallenge } from '../http/helpers.js';

// T01: код из письма и адрес получателя не попадают ни в одну запись журнала.
// Логгер здесь — обычный pino без скрытия полей: проверяем сами адаптеры, а
// не страховку в createLogger.

const CODE = '739182';
const TO = 'victim@corp.example';

function rawLogger(): { logger: pino.Logger; out: () => string } {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      lines.push(String(chunk));
      cb();
    },
  });
  return { logger: pino({ level: 'trace' }, stream), out: () => lines.join('') };
}

function resendClient(result: Awaited<ReturnType<ResendClientLike['emails']['send']>>): ResendClientLike {
  return { emails: { send: async () => result } };
}

const loginEmail = buildLoginCodeEmail({ to: TO, code: CODE, ttlMinutes: 15, appName: 'Auth Service' });
const linkEmail = buildGoogleLinkCodeEmail({ to: TO, code: CODE, ttlMinutes: 15, appName: 'Auth Service' });

describe('T01: журнал отправки писем', () => {
  it('ResendMailer: только id письма, тип письма и хеш адреса', async () => {
    const { logger, out } = rawLogger();
    const mailer = new ResendMailer(resendClient({ data: { id: 'msg-1' }, error: null }), 'a@b.c', logger);
    await mailer.send(loginEmail);
    await mailer.send(linkEmail);
    const log = out();
    expect(log).not.toContain(CODE);
    expect(log).not.toContain(TO);
    expect(log).toContain('msg-1');
    expect(log).toContain(sha256Hex(TO));
    expect(log).toContain('"kind":"login_code"');
    expect(log).toContain('"kind":"google_link_code"');
  });

  it('ResendMailer: ошибка провайдера тоже без кода и адреса', async () => {
    const { logger, out } = rawLogger();
    const mailer = new ResendMailer(
      resendClient({ data: null, error: { message: 'rate limited', name: 'rate_limit_exceeded' } }),
      'a@b.c',
      logger,
    );
    await expect(mailer.send(loginEmail)).rejects.toThrow();
    expect(out()).not.toContain(CODE);
    expect(out()).not.toContain(TO);
  });

  it('LogMailer: без кода и адреса', async () => {
    const { logger, out } = rawLogger();
    await new LogMailer(logger).send(loginEmail);
    expect(out()).not.toContain(CODE);
    expect(out()).not.toContain(TO);
    expect(out()).toContain(sha256Hex(TO));
  });

  it('весь вход по коду через HTTP: ни одна запись не содержит код или адрес', async () => {
    const { logger, out } = rawLogger();
    const deps = await makeTestDeps();
    deps.logger = logger;
    const mailer = new ResendMailer(resendClient({ data: { id: 'msg-2' }, error: null }), 'a@b.c', logger);
    deps.codeProvider = new EmailCodeProvider(new InMemoryLoginChallengeStore(), mailer, fakeClock(new Date()), {
      appName: 'Auth Service',
      codeTtlMinutes: 15,
      generateCode: () => CODE,
    });
    const app = buildServer(deps);
    const started = await app.inject({
      method: 'POST', url: '/authorize/identify', payload: authorizeForm({ email: TO }), headers: FORM_HEADERS,
    });
    const challenge = extractChallenge(started.body);
    await app.inject({
      method: 'POST', url: '/authorize/code/verify', payload: authorizeForm({ challenge, code: '000000' }), headers: FORM_HEADERS,
    });
    await app.inject({
      method: 'POST', url: '/authorize/code/verify', payload: authorizeForm({ challenge, code: CODE }), headers: FORM_HEADERS,
    });
    expect(out()).toContain('msg-2');
    expect(out()).not.toContain(CODE);
    expect(out()).not.toContain(TO);
    await app.close();
  });
});
