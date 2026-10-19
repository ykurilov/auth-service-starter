import { describe, it, expect } from 'vitest';
import { Writable } from 'node:stream';
import { loadConfig } from '../../../src/config/config.js';
import { MailDeliveryError } from '../../../src/ports/mailer.js';
import { buildServer } from '../../../src/adapters/http/server.js';
import { createLogger } from '../../../src/logging/logger.js';
import { GoogleProvider, type GoogleTokenPayload } from '../../../src/domain/google-login/google-provider.js';
import { GoogleNonceService } from '../../../src/domain/google-login/google-nonce.js';
import { InMemoryGoogleNonceStore } from '../../../src/adapters/repository/in-memory-google-nonce-store.js';
import { systemClock } from '../../../src/ports/clock.js';
import type { Client } from '../../../src/domain/clients/client.js';
import {
  makeTestDeps,
  type TestDeps,
  TEST_CSRF,
  TEST_VERIFIER,
  FORM_HEADERS,
  browserHeaders,
  authorizeForm,
  extractChallenge,
  startCodeLogin,
} from './helpers.js';

// Круг 5: двойное нажатие «Получить код», журнал без адреса и handle,
// очередь цепочки SSO без БД, тексты неподтверждённых писем.

const DEFAULT_LIMITS = loadConfig({ PUBLIC_ISSUER_URL: 'https://auth.example' } as NodeJS.ProcessEnv).rateLimits;

type App = ReturnType<typeof buildServer>;

function identify(app: App, email: string, headers: Record<string, string> = FORM_HEADERS, extra: Record<string, string> = {}) {
  return app.inject({ method: 'POST', url: '/authorize/identify', payload: authorizeForm({ email, ...extra }), headers });
}

function verify(app: App, challenge: string, code: string, headers: Record<string, string> = FORM_HEADERS) {
  return app.inject({ method: 'POST', url: '/authorize/code/verify', payload: authorizeForm({ challenge, code }), headers });
}

function resend(app: App, challenge: string) {
  return app.inject({ method: 'POST', url: '/authorize/code/request', payload: authorizeForm({ challenge }), headers: FORM_HEADERS });
}

const SECOND_CLIENT: Client = {
  id: 'other',
  type: 'external',
  redirectUris: ['https://other.example/cb'],
  allowedProviders: ['email'],
};
const FIRST_CLIENT: Client = {
  id: 'app',
  type: 'external',
  redirectUris: ['https://app.example/cb'],
  allowedProviders: ['email'],
};

describe('R5-B1: повторное «Получить код» из того же браузера', () => {
  it('два одновременных запроса: оба экрана кода одной попытки, одно письмо, код из него подходит', async () => {
    const deps = await makeTestDeps({ rateLimits: DEFAULT_LIMITS, codeSequence: ['111111', '222222'] });
    const app = buildServer(deps);
    const [a, b] = await Promise.all([identify(app, 'user@x.com'), identify(app, 'user@x.com')]);
    expect([a.statusCode, b.statusCode]).toEqual([200, 200]);
    expect(extractChallenge(a.body)).toBe(extractChallenge(b.body));
    expect(deps.mailer.sent).toHaveLength(1);
    expect((await verify(app, extractChallenge(b.body), '111111')).statusCode).toBe(302);
    await app.close();
  });

  it('повтор той же формы (обновление страницы без JS): тот же экран кода, нового письма нет', async () => {
    const deps = await makeTestDeps({ rateLimits: DEFAULT_LIMITS });
    const app = buildServer(deps);
    const first = await identify(app, 'user@x.com');
    deps.clock.advance(5);
    const again = await identify(app, 'user@x.com');
    expect(again.statusCode).toBe(200);
    expect(extractChallenge(again.body)).toBe(extractChallenge(first.body));
    expect(again.body).toContain('Код уже отправили');
    expect(deps.mailer.sent).toHaveLength(1);
    await app.close();
  });

  it('«Назад» к форме почты и новая отправка: та же попытка', async () => {
    const deps = await makeTestDeps({ rateLimits: DEFAULT_LIMITS });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    const back = await app.inject({
      method: 'GET',
      url: '/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_challenge=chal&code_challenge_method=S256&scope=openid&prompt=login',
      headers: { cookie: `csrf=${TEST_CSRF}` },
    });
    expect(back.statusCode).toBe(200);
    expect(back.body).toContain(`name="csrf" value="${TEST_CSRF}"`);
    const again = await identify(app, 'USER@x.com');
    expect(again.statusCode).toBe(200);
    expect(extractChallenge(again.body)).toBe(challenge);
    expect(deps.mailer.sent).toHaveLength(1);
    await app.close();
  });

  it('посторонний браузер на паузе по-прежнему получает 429 без попытки', async () => {
    const deps = await makeTestDeps({ rateLimits: DEFAULT_LIMITS });
    const app = buildServer(deps);
    await startCodeLogin(app, 'user@x.com');
    const other = await identify(app, 'user@x.com', browserHeaders('csrf-other'), { csrf: 'csrf-other' });
    expect(other.statusCode).toBe(429);
    expect(other.body).not.toContain('name="challenge"');
    expect(deps.mailer.sent).toHaveLength(1);
    await app.close();
  });

  it('другой клиент в том же браузере: попытка первого не подхватывается', async () => {
    const deps = await makeTestDeps({ rateLimits: DEFAULT_LIMITS, clients: [FIRST_CLIENT, SECOND_CLIENT] });
    const app = buildServer(deps);
    await startCodeLogin(app, 'user@x.com');
    const other = await identify(app, 'user@x.com', FORM_HEADERS, {
      client_id: 'other',
      redirect_uri: 'https://other.example/cb',
    });
    expect(other.statusCode).toBe(429);
    expect(other.body).not.toContain('name="challenge"');
    await app.close();
  });

  it('попытка, где проверки закончились, не подхватывается', async () => {
    const deps = await makeTestDeps({ rateLimits: DEFAULT_LIMITS });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    for (let i = 0; i < 5; i++) await verify(app, challenge, '000000');
    const again = await identify(app, 'user@x.com');
    expect(again.statusCode).toBe(429);
    await app.close();
  });

  it('пауза прошла: новая попытка и новое письмо, как раньше', async () => {
    const deps = await makeTestDeps({ rateLimits: DEFAULT_LIMITS });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    deps.clock.advance(61);
    const again = await identify(app, 'user@x.com');
    expect(again.statusCode).toBe(200);
    expect(extractChallenge(again.body)).not.toBe(challenge);
    expect(deps.mailer.sent).toHaveLength(2);
    await app.close();
  });
});

describe('R5-B1: кнопка формы блокируется после первого нажатия', () => {
  it('форма почты и форма переотправки блокируют кнопку и снимают блок при возврате на страницу', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const page = await app.inject({
      method: 'GET',
      url: '/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_challenge=chal&code_challenge_method=S256&scope=openid',
    });
    expect(page.body).toContain('data-submit-once');
    expect(page.body).toContain('pageshow');
    const code = await identify(app, 'user@x.com');
    expect(code.body).toMatch(/<form[^>]*data-submit-once[^>]*action="\/authorize\/code\/request"|<form[^>]*action="\/authorize\/code\/request"[^>]*data-submit-once/);
    await app.close();
  });
});

function capture(): { stream: Writable; out: () => string } {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      lines.push(String(chunk));
      cb();
    },
  });
  return { stream, out: () => lines.join('') };
}

describe('R5-B2: неподтверждённое письмо не уносит в журнал адрес и handle', () => {
  it('первое письмо без ответа провайдера: в журнале нет адреса и handle, есть тип и сообщение', async () => {
    const deps = await makeTestDeps();
    const log = capture();
    deps.logger = createLogger('info', log.stream);
    deps.mailer.send = async () => { throw new MailDeliveryError('нет ответа Resend за 10000 мс'); };
    const app = buildServer(deps);
    const res = await identify(app, 'victim@corp.example');
    expect(res.statusCode).toBe(503);
    const handle = extractChallenge(res.body);
    const out = log.out();
    expect(out).toContain('UnconfirmedCodeDeliveryError');
    expect(out).toContain('нет ответа Resend');
    expect(out).not.toContain('victim@corp.example');
    expect(out).not.toContain(handle);
    await app.close();
  });

  it('переотправка без ответа провайдера: то же', async () => {
    const deps = await makeTestDeps();
    const log = capture();
    deps.logger = createLogger('info', log.stream);
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'victim@corp.example');
    deps.mailer.send = async () => { throw new MailDeliveryError('timeout'); };
    const res = await resend(app, challenge);
    expect(res.statusCode).toBe(503);
    const out = log.out();
    expect(out).toContain('UnconfirmedCodeDeliveryError');
    expect(out).not.toContain('victim@corp.example');
    expect(out).not.toContain(challenge);
    await app.close();
  });
});

describe('R5: тексты неподтверждённых писем', () => {
  it('переотправка без ответа провайдера говорит, что прежний код больше не действует', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    deps.mailer.send = async () => { throw new MailDeliveryError('timeout'); };
    const res = await resend(app, challenge);
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain('прежний код больше не действует');
    await app.close();
  });

  it('первое письмо без ответа не говорит про прежний код', async () => {
    const deps = await makeTestDeps();
    deps.mailer.send = async () => { throw new MailDeliveryError('timeout'); };
    const app = buildServer(deps);
    const res = await identify(app, 'user@x.com');
    expect(res.statusCode).toBe(503);
    expect(res.body).not.toContain('прежний код');
    await app.close();
  });

  it('поток Google: экран кода после неподтверждённого письма сохраняет пояснение про адрес', async () => {
    const deps = await makeTestDeps({
      clients: [{ id: 'app', type: 'internal', redirectUris: ['https://app.example/cb'], allowedProviders: ['email', 'google'] }],
    });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const page = await app.inject({
      method: 'GET',
      url: '/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_challenge=chal&code_challenge_method=S256&scope=openid',
      headers: { cookie: `csrf=${TEST_CSRF}` },
    });
    const nonce = /nonce: '([^']+)'/.exec(page.body)![1]!;
    payloads.set('good-token', { sub: 'g-1', email: 'boss@corp.example', emailVerified: true, nonce });
    deps.mailer.send = async () => { throw new MailDeliveryError('timeout'); };
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/google',
      payload: authorizeForm({ credential: 'good-token' }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain('name="challenge"');
    expect(res.body).toContain('Google не подтверждает');
    expect(res.body).toContain('Не удалось подтвердить отправку письма');
    await app.close();
  });
});

function fakeGoogle(deps: TestDeps): Map<string, GoogleTokenPayload> {
  const payloads = new Map<string, GoogleTokenPayload>();
  deps.config.googleClientId = 'google-cid';
  deps.googleNonces = new GoogleNonceService(new InMemoryGoogleNonceStore(), systemClock);
  deps.googleProvider = new GoogleProvider(
    {
      verify: async (idToken: string) => {
        const p = payloads.get(idToken);
        if (!p) throw new Error('bad token');
        return p;
      },
    },
    deps.googleNonces,
  );
  return payloads;
}

describe('R5: тестовые настройки', () => {
  it('неизвестный ключ лимита — понятная ошибка, а не молчаливый пропуск', async () => {
    await expect(
      makeTestDeps({ rateLimits: { codeRequestPerEmail: { limit: 1, windowSeconds: 60 } } as never }),
    ).rejects.toThrow(/codeRequestPerEmail/);
  });
});

describe('R5: смена аккаунта без БД идёт по очереди цепочки', () => {
  // Смена аккаунта начинает новую цепочку (круг 10): каждый вход — в своей,
  // прежняя закрыта, ни в одной нет двух пользователей.
  it('два одновременных входа разными аккаунтами со старой SSO-cookie: у каждого своя новая цепочка', async () => {
    const deps = await makeTestDeps({
      clients: [{ id: 'app', type: 'internal', redirectUris: ['https://app.example/cb'], allowedProviders: ['email'] }],
    });
    const app = buildServer(deps);
    const login = (challenge: string, sso?: string) =>
      app.inject({
        method: 'POST',
        url: '/authorize/code/verify',
        headers: { ...FORM_HEADERS, ...(sso ? { cookie: `csrf=${TEST_CSRF}; sso=${sso}` } : {}) },
        payload: authorizeForm({ challenge, code: 'CODE55' }),
      });
    const exchange = (location: string) =>
      app.inject({
        method: 'POST',
        url: '/oauth/token',
        payload: {
          grant_type: 'authorization_code',
          code: new URL(location).searchParams.get('code')!,
          client_id: 'app',
          redirect_uri: 'https://app.example/cb',
          code_verifier: TEST_VERIFIER,
        },
      });
    const first = await login(await startCodeLogin(app, 'carol@x.com'));
    const previous = first.cookies.find((c) => c.name === 'sso')!.value;
    const a = await startCodeLogin(app, 'alice@x.com');
    const b = await startCodeLogin(app, 'bob@x.com');
    // Оба входа доходят до SSO-сервиса вместе; дальше — обычный порядок.
    let arrivals = 0;
    let release!: () => void;
    const both = new Promise<void>((r) => (release = r));
    const original = deps.sso.start.bind(deps.sso);
    deps.sso.start = async (...args) => {
      if (++arrivals === 2) release();
      await both;
      return original(...args);
    };
    const [alice, bob] = await Promise.all([login(a, previous), login(b, previous)]);
    expect([alice.statusCode, bob.statusCode]).toEqual([302, 302]);
    const chains = [];
    for (const res of [alice, bob]) {
      const session = await deps.sso.resolve(res.cookies.find((c) => c.name === 'sso')!.value);
      chains.push(session!.chainId);
    }
    expect(await deps.sso.resolve(previous)).toBeNull();
    expect(new Set(chains).size).toBe(2);
    const tokens = await Promise.all([exchange(String(alice.headers.location)), exchange(String(bob.headers.location))]);
    expect(tokens.map((t) => t.statusCode)).toEqual([200, 200]);
    await app.close();
  });
});
