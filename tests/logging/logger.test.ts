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
