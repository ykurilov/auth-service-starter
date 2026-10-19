import { describe, it, expect } from 'vitest';
import { Writable } from 'node:stream';
import { createLogger } from '../../src/logging/logger.js';

function capture(): { stream: Writable; lines: string[] } {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      lines.push(String(chunk));
      cb();
    },
  });
  return { stream, lines };
}

describe('T01: логгер скрывает заведомо секретные поля', () => {
  it('код, адрес, тема письма и токены не попадают в запись', () => {
    const { stream, lines } = capture();
    const logger = createLogger('info', stream);
    logger.info({
      code: '739182',
      to: 'victim@corp.example',
      email: 'victim@corp.example',
      subject: '739182 — код для входа',
      text: 'Код: 739182',
      html: '<b>739182</b>',
      token: 'tok-S3CR3T',
      refreshToken: 'rt-S3CR3T',
      refresh_token: 'rt-S3CR3T',
      access_token: 'at-S3CR3T',
      id_token: 'idt-S3CR3T',
      credential: 'google-jwt',
      password: 'pw-S3CR3T',
      client_secret: 'cs-S3CR3T',
      authorization: 'Bearer abc-S3CR3T',
      cookie: 'sso=cookie-S3CR3T',
      emailId: 'msg-1',
    }, 'проверка');
    const out = lines.join('');
    for (const secret of ['739182', 'victim@corp.example', 'S3CR3T', 'google-jwt']) expect(out).not.toContain(secret);
    expect(out).toContain('msg-1');
  });

  it('вложенные поля и заголовки запроса тоже скрываются', () => {
    const { stream, lines } = capture();
    const logger = createLogger('info', stream);
    logger.warn({
      email: { to: 'victim@corp.example', subject: '739182' },
      req: { headers: { authorization: 'Bearer abc-S3CR3T', cookie: 'sso=cookie-S3CR3T' } },
      headers: { authorization: 'Bearer abc-S3CR3T', cookie: 'csrf=cookie-S3CR3T' },
    }, 'проверка');
    const out = lines.join('');
    for (const secret of ['739182', 'victim@corp.example', 'S3CR3T']) expect(out).not.toContain(secret);
  });
});

describe('P3-1: глубокое скрытие и код ошибки', () => {
  it('новые секретные ключи скрываются на любой глубине, в том числе в массивах', () => {
    const { stream, lines } = capture();
    const logger = createLogger('info', stream);
    logger.info({
      state: 'st-S3CR3T',
      a: { b: { c: { nonce: 'n-S3CR3T', code_verifier: 'v-S3CR3T', refresh: 'r-S3CR3T' } } },
      list: [{ deep: { secret: 's-S3CR3T', 'set-cookie': 'sc-S3CR3T' } }],
      headers: { 'X-Api-Key': 'k-S3CR3T', 'x-admin-token': 'adm-S3CR3T' },
      cfg: { nested: { adminApiToken: 'cfg-S3CR3T', ADMIN_API_TOKEN: 'env-S3CR3T' } },
      safe: { level: { deeper: 'visible-value' } },
    }, 'проверка');
    const out = lines.join('');
    expect(out).not.toContain('S3CR3T');
    expect(out).toContain('visible-value');
  });

  it('код ошибки в поле errorCode и в err.code остаётся виден', () => {
    const { stream, lines } = capture();
    const logger = createLogger('info', stream);
    logger.info({ errorCode: 'FST_ERR_CTP_INVALID_MEDIA_TYPE', status: 415 }, 'некорректный запрос');
    const err = Object.assign(new Error('boom'), { code: 'ECONNREFUSED' });
    logger.error({ err }, 'сбой');
    const out = lines.join('');
    expect(out).toContain('FST_ERR_CTP_INVALID_MEDIA_TYPE');
    expect(out).toContain('ECONNREFUSED');
    expect(out).toContain('boom');
    expect(out).toContain('"stack"');
  });
});

describe('R4: общий объект и предел глубины', () => {
  it('объект, встреченный второй раз по другой ссылке, тоже скрывается', () => {
    const { stream, lines } = capture();
    const logger = createLogger('info', stream);
    const shared = { code: '739182', id: 'msg-1' };
    logger.info({ first: shared, second: shared, list: [shared] }, 'проверка');
    const out = lines.join('');
    expect(out).not.toContain('739182');
    expect(out.match(/msg-1/g)).toHaveLength(3);
  });

  it('цикл не роняет запись и не раскрывает поля', () => {
    const { stream, lines } = capture();
    const logger = createLogger('info', stream);
    const node: Record<string, unknown> = { token: 'tok-S3CR3T' };
    node.self = node;
    logger.info({ node }, 'проверка');
    expect(lines.join('')).not.toContain('S3CR3T');
  });

  it('глубже предела объект не выводится как есть', () => {
    const { stream, lines } = capture();
    const logger = createLogger('info', stream);
    let deep: Record<string, unknown> = { password: 'pw-S3CR3T' };
    for (let i = 0; i < 12; i++) deep = { inner: deep };
    logger.info({ deep }, 'проверка');
    expect(lines.join('')).not.toContain('S3CR3T');
  });
});

describe('R5: объекты ошибок проходят через фильтр', () => {
  it('прикреплённые к ошибке данные не попадают в запись, тип, сообщение, код и стек остаются', () => {
    const { stream, lines } = capture();
    const logger = createLogger('info', stream);
    const err = Object.assign(new TypeError('сбой доставки'), {
      code: 'ETIMEDOUT',
      challenge: { handle: 'handle-S3CR3T', email: 'victim@corp.example' },
      detail: 'Key (email)=(victim@corp.example) already exists',
      response: { headers: { authorization: 'Bearer abc-S3CR3T' } },
    });
    logger.error({ err, nested: { failure: err } }, 'сбой');
    const out = lines.join('');
    expect(out).not.toContain('S3CR3T');
    expect(out).not.toContain('victim@corp.example');
    const record = JSON.parse(out);
    expect(record.err).toMatchObject({ type: 'TypeError', message: 'сбой доставки', code: 'ETIMEDOUT' });
    expect(record.err.stack).toContain('сбой доставки');
    expect(record.nested.failure).toMatchObject({ type: 'TypeError', code: 'ETIMEDOUT' });
  });

  it('причина ошибки (cause) тоже фильтруется', () => {
    const { stream, lines } = capture();
    const logger = createLogger('info', stream);
    const cause = Object.assign(new Error('нет ответа'), { email: 'victim@corp.example', code: 'ECONNRESET' });
    const err = new Error('письмо не отправлено', { cause });
    logger.error({ err }, 'сбой');
    const out = lines.join('');
    expect(out).not.toContain('victim@corp.example');
    const record = JSON.parse(out);
    expect(record.err.cause).toMatchObject({ type: 'Error', message: 'нет ответа', code: 'ECONNRESET' });
  });

  it('код ошибки, который не строка и не число, не выводится', () => {
    const { stream, lines } = capture();
    const logger = createLogger('info', stream);
    const err = Object.assign(new Error('boom'), { code: { otp: '739182' } });
    logger.error({ err }, 'сбой');
    expect(lines.join('')).not.toContain('739182');
  });
});
