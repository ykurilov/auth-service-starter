import { describe, it, expect, vi } from 'vitest';
import { domainToASCII } from 'node:url';
import { loadConfig } from '../../../src/config/config.js';
import { MailDeliveryError } from '../../../src/ports/mailer.js';
import { buildServer } from '../../../src/adapters/http/server.js';
import { GoogleProvider, type GoogleTokenPayload } from '../../../src/domain/google-login/google-provider.js';
import { GoogleNonceService } from '../../../src/domain/google-login/google-nonce.js';
import { InMemoryGoogleNonceStore } from '../../../src/adapters/repository/in-memory-google-nonce-store.js';
import { systemClock } from '../../../src/ports/clock.js';
import type { Client } from '../../../src/domain/clients/client.js';
import {
  makeTestDeps,
  type TestDeps,
  TEST_CSRF,
  FORM_HEADERS,
  extractChallenge,
  startCodeLogin,
} from './helpers.js';

// Аудит, раунд 3: лимиты отправки кода, переотправка, проверка политики до
// гашения кода, ошибки протокола в JS-режиме, CSRF двух вкладок, адреса с
// кириллическим доменом.

type App = ReturnType<typeof buildServer>;

const DEFAULT_LIMITS = loadConfig({ PUBLIC_ISSUER_URL: 'https://auth.example' } as NodeJS.ProcessEnv).rateLimits;
const REPLACE = { ...FORM_HEADERS, 'x-auth-navigation': 'replace' };

function oidc(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    client_id: 'app',
    redirect_uri: 'https://app.example/cb',
    code_challenge: 'chalchalchalchalchalchalchalchalchalchalchal',
    code_challenge_method: 'S256',
    scope: 'openid',
    state: 'st1',
    csrf: TEST_CSRF,
    ...overrides,
  };
}

function identify(app: App, email: string, headers: Record<string, string> = FORM_HEADERS, csrf = TEST_CSRF) {
  return app.inject({
    method: 'POST',
    url: '/authorize/identify',
    payload: new URLSearchParams({ ...oidc({ csrf }), email }).toString(),
    headers,
  });
}

function resend(app: App, challenge: string, headers: Record<string, string> = FORM_HEADERS) {
  return app.inject({
    method: 'POST',
    url: '/authorize/code/request',
    payload: new URLSearchParams({ ...oidc(), challenge }).toString(),
    headers,
  });
}

function verify(app: App, challenge: string, code: string, headers: Record<string, string> = FORM_HEADERS) {
  return app.inject({
    method: 'POST',
    url: '/authorize/code/verify',
    payload: new URLSearchParams({ ...oidc(), challenge, code }).toString(),
    headers,
  });
}

function fromIp(ip: string): Record<string, string> {
  return { ...FORM_HEADERS, 'x-forwarded-for': ip };
}

const GOOGLE_CLIENT: Client = {
  id: 'app',
  type: 'internal',
  redirectUris: ['https://app.example/cb'],
  allowedProviders: ['email', 'google'],
};

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

const AUTHORIZE_URL =
  '/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb' +
  '&code_challenge=chalchalchalchalchalchalchalchalchalchalchal&code_challenge_method=S256&scope=openid&state=st1';

async function renderNonce(app: App): Promise<string> {
  const res = await app.inject({ method: 'GET', url: AUTHORIZE_URL, headers: { cookie: `csrf=${TEST_CSRF}` } });
  const m = /nonce: '([^']+)'/.exec(res.body);
  if (!m) throw new Error('на странице нет nonce Google');
  return m[1]!;
}

describe('T06: лимит по адресу считает только новые попытки', () => {
  it('дефолт по адресу — короткая пауза между письмами, а не часовой отказ', () => {
    expect(DEFAULT_LIMITS.codeRequestEmailPause.windowSeconds).toBeLessThanOrEqual(60);
  });

  it('посторонний исчерпал лимит адреса — переотправка в живой попытке владельца работает', async () => {
    const deps = await makeTestDeps({
      trustProxy: 1,
      rateLimits: { codeRequestPerEmailDaily: { limit: 2, windowSeconds: 86400 } },
    });
    const app = buildServer(deps);
    const owner = await startCodeLogin(app, 'owner@x.com', {}, fromIp('198.51.100.1'));
    deps.clock.advance(60);
    expect((await identify(app, 'owner@x.com', fromIp('203.0.113.1'))).statusCode).toBe(200);
    deps.clock.advance(60);
    expect((await identify(app, 'owner@x.com', fromIp('203.0.113.2'))).statusCode).toBe(429);
    const res = await resend(app, owner, fromIp('198.51.100.1'));
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Отправили новый код');
    await app.close();
  });
});

describe('T07: честный пользователь и понятная страница лимита', () => {
  it('вход, 3 переотправки и новый вход с дефолтными лимитами проходят', async () => {
    const deps = await makeTestDeps({ rateLimits: DEFAULT_LIMITS });
    const app = buildServer(deps);
    const first = await startCodeLogin(app, 'user@x.com');
    for (let i = 0; i < 3; i++) expect((await resend(app, first)).statusCode).toBe(200);
    // Новое письмо на тот же адрес — после паузы между письмами.
    deps.clock.advance(60);
    expect((await identify(app, 'user@x.com')).statusCode).toBe(200);
    deps.clock.advance(60);
    expect((await identify(app, 'user@x.com')).statusCode).toBe(200);
    await app.close();
  });

  it('страница 429 называет время ожидания из Retry-After', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeRequest: { limit: 1, windowSeconds: 900 } } });
    const app = buildServer(deps);
    await startCodeLogin(app, 'user@x.com');
    const res = await identify(app, 'user@x.com');
    expect(res.statusCode).toBe(429);
    expect(res.headers['retry-after']).toBe('900');
    expect(res.body).toContain('15 мин');
    expect(res.body).not.toContain('Попробуйте позже');
    await app.close();
  });

  it('класс в одной сети: дефолтный лимит писем на IP заметно больше 20 и настраивается', () => {
    expect(DEFAULT_LIMITS.codeRequestPerIp.limit).toBeGreaterThanOrEqual(100);
    const custom = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example',
      CODE_REQUEST_PER_IP_HOURLY: '500',
    } as NodeJS.ProcessEnv).rateLimits;
    expect(custom.codeRequestPerIp).toEqual({ limit: 500, windowSeconds: 3600 });
  });

  it('30 учеников за одним IP входят с переотправкой', async () => {
    const deps = await makeTestDeps({ rateLimits: DEFAULT_LIMITS });
    const app = buildServer(deps);
    for (let i = 0; i < 30; i++) {
      const challenge = await startCodeLogin(app, `student${i}@school.example`);
      expect((await resend(app, challenge)).statusCode).toBe(200);
    }
    await app.close();
  });

  it('переотправки по-прежнему тратят общий бюджет IP (защита от рассылки)', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeRequestPerIp: { limit: 2, windowSeconds: 3600 } } });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    expect((await resend(app, challenge)).statusCode).toBe(200);
    expect((await resend(app, challenge)).statusCode).toBe(429);
    await app.close();
  });
});

describe('T08: переотправка меняет код только после успешной отправки', () => {
  it('отказ провайдера: прежний код работает, переотправка не списана', async () => {
    const deps = await makeTestDeps({ codeSequence: ['111111', '222222', '333333', '444444', '555555'] });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    const send = deps.mailer.send.bind(deps.mailer);
    deps.mailer.send = async () => { throw new MailDeliveryError('422', 'rejected'); };
    expect((await resend(app, challenge)).statusCode).toBe(503);
    deps.mailer.send = send;
    const view = await deps.codeProvider.describe({ handle: challenge, binding: TEST_CSRF });
    expect(view?.resendsLeft).toBe(3);
    expect((await verify(app, challenge, '111111')).statusCode).toBe(302);
    await app.close();
  });

  it('уведомление говорит, что прежний код больше не действует', async () => {
    const app = buildServer(await makeTestDeps());
    const challenge = await startCodeLogin(app, 'user@x.com');
    const res = await resend(app, challenge);
    expect(res.body).toContain('прежний код больше не действует');
    await app.close();
  });
});

describe('T16, T24: политика клиента до гашения кода', () => {
  it('провайдер email запрещён после отправки кода: попытка не тратится, JS получает адрес перехода', async () => {
    const deps = await makeTestDeps({ clients: [{ ...GOOGLE_CLIENT }] });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    await deps.adminClients!.update('app', { allowedProviders: ['google'] });
    const res = await verify(app, challenge, 'CODE55', REPLACE);
    expect(res.statusCode).toBe(200);
    const redirectTo = new URL(res.json<{ redirectTo: string }>().redirectTo);
    expect(redirectTo.origin + redirectTo.pathname).toBe('https://app.example/cb');
    expect(redirectTo.searchParams.get('error')).toBe('unauthorized_client');
    expect(redirectTo.searchParams.get('state')).toBe('st1');
    const view = await deps.codeProvider.describe({ handle: challenge, binding: TEST_CSRF });
    expect(view?.attemptsLeft).toBe(5);
    await app.close();
  });

  it('без JavaScript та же ошибка — обычный редирект', async () => {
    const deps = await makeTestDeps({ clients: [{ ...GOOGLE_CLIENT }] });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    await deps.adminClients!.update('app', { allowedProviders: ['google'] });
    const res = await verify(app, challenge, 'CODE55');
    expect(res.statusCode).toBe(302);
    expect(res.headers['location'] as string).toContain('error=unauthorized_client');
    await app.close();
  });

  it('PKCE-ошибка на verify в JS-режиме — JSON с адресом перехода', async () => {
    const app = buildServer(await makeTestDeps());
    const challenge = await startCodeLogin(app, 'user@x.com');
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/code/verify',
      payload: new URLSearchParams({ ...oidc({ code_challenge_method: 'plain' }), challenge, code: 'CODE55' }).toString(),
      headers: REPLACE,
    });
    expect(res.statusCode).toBe(200);
    expect(res.json<{ redirectTo: string }>().redirectTo).toContain('error=invalid_request');
    await app.close();
  });

  it('клиенту без email форма почты не рисуется', async () => {
    const deps = await makeTestDeps({ clients: [{ ...GOOGLE_CLIENT, allowedProviders: ['google'] }] });
    fakeGoogle(deps);
    const app = buildServer(deps);
    const res = await app.inject({ method: 'GET', url: AUTHORIZE_URL });
    expect(res.statusCode).toBe(200);
    expect(res.body).not.toContain('action="/authorize/identify"');
    expect(res.body).toContain('google-btn');
    await app.close();
  });

  it('T24: сбой после верного кода — понятное сообщение и путь к новому входу', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    vi.spyOn(deps.login, 'completeLogin').mockRejectedValueOnce(new Error('db down'));
    const res = await verify(app, challenge, 'CODE55', REPLACE);
    expect(res.statusCode).toBe(500);
    const body = res.json<{ error: string; restartTo: string }>();
    expect(body.error).toContain('начните вход заново');
    expect(new URL(body.restartTo, 'https://auth.example').searchParams.get('prompt')).toBe('login');
    await app.close();
  });
});

describe('T19: нет code_challenge при проверенных client_id и redirect_uri', () => {
  it('редирект invalid_request, а не страница 400', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'GET',
      url: '/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid&state=s9',
    });
    expect(res.statusCode).toBe(302);
    const loc = new URL(res.headers['location'] as string);
    expect(loc.searchParams.get('error')).toBe('invalid_request');
    expect(loc.searchParams.get('state')).toBe('s9');
    await app.close();
  });

  it('неизвестный redirect_uri без code_challenge — по-прежнему страница, не редирект', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'GET',
      url: '/authorize?client_id=app&redirect_uri=https%3A%2F%2Fevil.example%2Fcb',
    });
    expect(res.statusCode).toBe(400);
    expect(res.headers['location']).toBeUndefined();
    await app.close();
  });
});

describe('P3-7: окончательный отказ провайдера', () => {
  it('первый шаг: «не удалось отправить», попытки нет, бюджет не списан', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeRequest: { limit: 1, windowSeconds: 900 } } });
    const send = deps.mailer.send.bind(deps.mailer);
    deps.mailer.send = async () => { throw new MailDeliveryError('rejected by provider', 'rejected'); };
    const app = buildServer(deps);
    const res = await identify(app, 'user@x.com');
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain('Не удалось отправить письмо');
    expect(res.body).not.toContain('name="challenge"');
    deps.mailer.send = send;
    expect((await identify(app, 'user@x.com')).statusCode).toBe(200);
    await app.close();
  });

  it('повторная отправка: бюджет IP не списан', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeRequestPerIp: { limit: 2, windowSeconds: 3600 } } });
    const app = buildServer(deps);
    const challenge = await startCodeLogin(app, 'user@x.com');
    const send = deps.mailer.send.bind(deps.mailer);
    deps.mailer.send = async () => { throw new MailDeliveryError('rejected by provider', 'rejected'); };
    expect((await resend(app, challenge)).statusCode).toBe(503);
    deps.mailer.send = send;
    expect((await resend(app, challenge)).statusCode).toBe(200);
    await app.close();
  });
});

describe('T21: письмо на первом шаге не подтвердилось', () => {
  it('экран кода с попыткой: код из запоздавшего письма подходит', async () => {
    const deps = await makeTestDeps();
    const send = deps.mailer.send.bind(deps.mailer);
    deps.mailer.send = async () => { throw new MailDeliveryError('timeout'); };
    const app = buildServer(deps);
    const res = await identify(app, 'user@x.com');
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain('Если письмо всё же придёт');
    const challenge = extractChallenge(res.body);
    deps.mailer.send = send;
    expect((await verify(app, challenge, 'CODE55')).statusCode).toBe(302);
    await app.close();
  });
});

describe('T22: имя из Google не попадает в письмо о привязке', () => {
  it('письмо владельцу адреса без имени, заданного посторонним', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    const payloads = fakeGoogle(deps);
    const app = buildServer(deps);
    const nonce = await renderNonce(app);
    payloads.set('t', {
      sub: 'g-x', email: 'boss@corp.example', emailVerified: true, name: 'Служба безопасности', nonce,
    });
    const res = await app.inject({
      method: 'POST',
      url: '/authorize/google',
      payload: new URLSearchParams({ ...oidc(), credential: 't' }).toString(),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(200);
    expect(deps.mailer.last?.to).toBe('boss@corp.example');
    expect(deps.mailer.last?.text).not.toContain('Служба безопасности');
    expect(deps.mailer.last?.html).not.toContain('Служба безопасности');
    await app.close();
  });
});

describe('T23: кнопка Google при исчерпанном лимите', () => {
  it('вместо пропавшей кнопки — пояснение', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    fakeGoogle(deps);
    deps.config.rateLimits.googleNoncePerIp = { limit: 1, windowSeconds: 900 };
    const app = buildServer(deps);
    await app.inject({ method: 'GET', url: AUTHORIZE_URL });
    const limited = await app.inject({ method: 'GET', url: AUTHORIZE_URL });
    expect(limited.body).not.toContain('google-btn');
    expect(limited.body).toContain('Вход через Google временно недоступен');
    await app.close();
  });

  it('выпуск nonce считается отдельно от POST /authorize/google', async () => {
    const deps = await makeTestDeps({ clients: [GOOGLE_CLIENT] });
    fakeGoogle(deps);
    deps.config.rateLimits.identifyPerIp = { limit: 1, windowSeconds: 900 };
    const app = buildServer(deps);
    await app.inject({ method: 'GET', url: AUTHORIZE_URL });
    expect((await app.inject({ method: 'GET', url: AUTHORIZE_URL })).body).toContain('google-btn');
    await app.close();
  });
});

describe('T25: адрес с кириллическим доменом', () => {
  it('принимается: письмо уходит на punycode, на странице — как ввели', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await identify(app, 'Ivan@Почта.РФ');
    expect(res.statusCode).toBe(200);
    expect(deps.mailer.last?.to).toBe(`ivan@${domainToASCII('почта.рф')}`);
    expect(res.body).toContain('ivan@почта.рф');
    await app.close();
  });

  it('кириллица в имени до @ по-прежнему отклоняется', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await identify(app, 'иван@почта.рф');
    expect(res.statusCode).toBe(400);
    expect(deps.mailer.sent).toHaveLength(0);
    await app.close();
  });
});

describe('T28: CSRF-cookie двух вкладок при первом заходе', () => {
  it('тихий шаг prompt=none уже выдаёт csrf-cookie', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({ method: 'GET', url: `${AUTHORIZE_URL}&prompt=none` });
    expect(res.statusCode).toBe(302);
    const setCookie = ([] as string[]).concat(res.headers['set-cookie'] ?? []);
    expect(setCookie.some((c) => c.startsWith('csrf='))).toBe(true);
    await app.close();
  });

  it('форма первой вкладки с перезаписанным токеном — форма заново, адрес сохранён', async () => {
    const deps = await makeTestDeps();
    const app = buildServer(deps);
    const res = await identify(app, 'user@x.com', { ...FORM_HEADERS, cookie: 'csrf=second-tab-token' }, 'first-tab-token');
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('action="/authorize/identify"');
    expect(res.body).toContain('value="user@x.com"');
    expect(res.body).toContain('name="csrf" value="second-tab-token"');
    expect(deps.mailer.sent).toHaveLength(0);
    await app.close();
  });

  it('чужой origin с несовпавшим токеном — по-прежнему отказ', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await identify(
      app, 'user@x.com', { ...FORM_HEADERS, cookie: 'csrf=second-tab-token', origin: 'https://evil.example' }, 'x',
    );
    expect(res.statusCode).toBe(400);
    await app.close();
  });
});
