import { describe, it, expect } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CSRF, FORM_HEADERS, authorizeForm, extractChallenge } from './helpers.js';
import { loginPage } from '../../../src/adapters/http/views/login-page.js';
import { pageLayout } from '../../../src/adapters/http/views/page-layout.js';
import type { Client } from '../../../src/domain/clients/client.js';
import type { OidcParams } from '../../../src/adapters/http/views/oidc-params.js';

const LOGOUT_CLIENT: Client = {
  id: 'app',
  type: 'internal',
  redirectUris: ['https://app.example/cb'],
  allowedProviders: ['email'],
};

const PARAMS: OidcParams = {
  client_id: 'app',
  redirect_uri: 'https://app.example/cb',
  code_challenge: 'chalchalchalchalchalchalchalchalchalchalchal',
  code_challenge_method: 'S256',
  scope: 'openid',
  state: 'st1',
};

function getCookie(res: { headers: Record<string, unknown> }, name: string): string {
  const raw = res.headers['set-cookie'];
  const arr = Array.isArray(raw) ? raw : [String(raw ?? '')];
  for (const line of arr) {
    const m = new RegExp(`${name}=([^;]+)`).exec(line);
    if (m && m[1] !== undefined) return m[1];
  }
  throw new Error(`cookie ${name} not found`);
}

async function loginAndGetSso(app: Awaited<ReturnType<typeof buildServer>>): Promise<string> {
  const identify = await app.inject({
    method: 'POST',
    url: '/authorize/identify',
    payload: authorizeForm({ email: 'user@x.com' }),
    headers: FORM_HEADERS,
  });
  const res = await app.inject({
    method: 'POST',
    url: '/authorize/code/verify',
    payload: authorizeForm({ challenge: extractChallenge(identify.body), code: 'CODE55' }),
    headers: FORM_HEADERS,
  });
  return getCookie(res, 'sso');
}

describe('п.1: страницы отказов ведут назад', () => {
  it('429 на отправке кода: ссылка на вход с теми же параметрами', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeRequest: { limit: 1, windowSeconds: 60 } } });
    const app = buildServer(deps);
    const send = () =>
      app.inject({
        method: 'POST', url: '/authorize/identify',
        payload: authorizeForm({ email: 'a@x.com' }), headers: FORM_HEADERS,
      });
    await send();
    const res = await send();
    expect(res.statusCode).toBe(429);
    expect(res.body).toContain('href="/authorize?client_id=app');
    expect(res.body).toContain('prompt=login');
    await app.close();
  });

  it('429 на проверке кода: ссылка на вход', async () => {
    const deps = await makeTestDeps({ rateLimits: { codeVerifyPerIp: { limit: 1, windowSeconds: 60 } } });
    const app = buildServer(deps);
    const challenge = extractChallenge(
      (await app.inject({
        method: 'POST', url: '/authorize/identify',
        payload: authorizeForm({ email: 'a@x.com' }), headers: FORM_HEADERS,
      })).body,
    );
    const verify = () =>
      app.inject({
        method: 'POST', url: '/authorize/code/verify',
        payload: authorizeForm({ challenge, code: '000000' }), headers: FORM_HEADERS,
      });
    await verify();
    const res = await verify();
    expect(res.statusCode).toBe(429);
    expect(res.body).toContain('href="/authorize?client_id=app');
    await app.close();
  });

  it('«Сессия формы истекла» на входе: ссылка на вход', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'POST', url: '/authorize/identify',
      payload: authorizeForm({ email: 'a@x.com' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.body).toContain('Сессия формы истекла');
    expect(res.body).toContain('href="/authorize?client_id=app');
    await app.close();
  });

  it('«Сессия формы истекла» на выходе: ссылка на страницу выхода', async () => {
    const app = buildServer(await makeTestDeps({ clients: [LOGOUT_CLIENT] }));
    const res = await app.inject({
      method: 'POST', url: '/logout',
      payload: new URLSearchParams({ client_id: 'app', csrf: 'x' }).toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.body).toContain('href="/logout?client_id=app');
    await app.close();
  });
});

describe('п.2: выход без cookie говорит честно', () => {
  it('нет ни SSO-cookie, ни cookie привязки — не обещает выход из всех сессий', async () => {
    const app = buildServer(await makeTestDeps({ clients: [LOGOUT_CLIENT] }));
    const res = await app.inject({
      method: 'POST', url: '/logout',
      payload: new URLSearchParams({ client_id: 'app', csrf: TEST_CSRF }).toString(),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('из этого приложения');
    expect(res.body).toContain('истекут сами');
    expect(res.body).not.toContain('Вы вышли из аккаунта.');
    await app.close();
  });

  it('с активной SSO-cookie — прежний текст', async () => {
    const app = buildServer(await makeTestDeps({ clients: [LOGOUT_CLIENT] }));
    const sso = await loginAndGetSso(app);
    const res = await app.inject({
      method: 'POST', url: '/logout',
      payload: new URLSearchParams({ client_id: 'app', csrf: TEST_CSRF }).toString(),
      headers: { ...FORM_HEADERS, cookie: `${FORM_HEADERS.cookie}; sso=${sso}` },
    });
    expect(res.body).toContain('Вы вышли из аккаунта');
    await app.close();
  });
});

describe('п.3: отказ на экране согласия', () => {
  async function consent(app: Awaited<ReturnType<typeof buildServer>>) {
    const sso = await loginAndGetSso(app);
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams(PARAMS as unknown as Record<string, string>).toString()}`,
      headers: { cookie: `sso=${sso}` },
    });
    return { sso, csrfCookie: getCookie(res, 'csrf'), csrfField: /name="csrf" value="([^"]+)"/.exec(res.body)![1]!, body: res.body };
  }

  it('на экране есть форма отказа', async () => {
    const app = buildServer(await makeTestDeps());
    const { body } = await consent(app);
    expect(body).toContain('action="/authorize/deny"');
    expect(body).toContain('Отказаться');
    await app.close();
  });

  it('отказ возвращает в приложение error=access_denied и state', async () => {
    const app = buildServer(await makeTestDeps());
    const { sso, csrfCookie, csrfField } = await consent(app);
    const res = await app.inject({
      method: 'POST', url: '/authorize/deny',
      payload: new URLSearchParams({ ...PARAMS, csrf: csrfField } as Record<string, string>).toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sso=${sso}; csrf=${csrfCookie}` },
    });
    expect(res.statusCode).toBe(302);
    const location = new URL(res.headers['location'] as string);
    expect(location.origin + location.pathname).toBe('https://app.example/cb');
    expect(location.searchParams.get('error')).toBe('access_denied');
    expect(location.searchParams.get('state')).toBe('st1');
    expect(location.searchParams.get('code')).toBeNull();
    await app.close();
  });

  it('чужой redirect_uri — отказ страницей, не редиректом', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'POST', url: '/authorize/deny',
      payload: authorizeForm({ redirect_uri: 'https://evil.example/cb' }),
      headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(400);
    expect(res.headers['location']).toBeUndefined();
    await app.close();
  });

  it('без csrf — отказ страницей', async () => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'POST', url: '/authorize/deny',
      payload: authorizeForm({}),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.headers['location']).toBeUndefined();
    await app.close();
  });
});

describe('п.4: код с пробелом или дефисом внутри', () => {
  it.each(['CO DE-55', ' CODE 55 ', 'code55'.toUpperCase()])('принимается: %j', async (typed) => {
    const app = buildServer(await makeTestDeps());
    const challenge = extractChallenge(
      (await app.inject({
        method: 'POST', url: '/authorize/identify',
        payload: authorizeForm({ email: 'a@x.com' }), headers: FORM_HEADERS,
      })).body,
    );
    const res = await app.inject({
      method: 'POST', url: '/authorize/code/verify',
      payload: authorizeForm({ challenge, code: typed }), headers: FORM_HEADERS,
    });
    expect(res.statusCode).toBe(302);
    expect(res.headers['location']).toContain('code=');
    await app.close();
  });
});

describe('п.5: адрес почты после исчерпания попытки', () => {
  it('исчерпанные проверки — на форме почты введённый адрес, не punycode', async () => {
    const app = buildServer(await makeTestDeps());
    const email = 'ivan@пример.рф';
    const challenge = extractChallenge(
      (await app.inject({
        method: 'POST', url: '/authorize/identify',
        payload: authorizeForm({ email }), headers: FORM_HEADERS,
      })).body,
    );
    let last = await app.inject({ method: 'GET', url: '/live' });
    for (let i = 0; i < 6; i++) {
      last = await app.inject({
        method: 'POST', url: '/authorize/code/verify',
        payload: authorizeForm({ challenge, code: '000000' }), headers: FORM_HEADERS,
      });
    }
    expect(last.body).toContain('name="email"');
    expect(last.body).toContain('value="ivan@пример.рф"');
    expect(last.body).not.toContain('xn--');
    await app.close();
  });

  it('форма кода несёт адрес-подсказку, и истёкшая попытка подставляет его в поле почты', async () => {
    const app = buildServer(await makeTestDeps());
    const page = loginPage({ params: PARAMS, mode: 'code', email: 'ivan@пример.рф', challenge: 'h1' });
    expect(page.match(/name="email_hint" value="ivan@пример.рф"/g)).toHaveLength(2);
    const res = await app.inject({
      method: 'POST', url: '/authorize/code/request',
      payload: authorizeForm({ challenge: 'unknown-handle', email_hint: 'ivan@пример.рф' }),
      headers: FORM_HEADERS,
    });
    expect(res.body).toContain('value="ivan@пример.рф"');
    await app.close();
  });
});

describe('п.6: Google без скрипта', () => {
  it('рядом с кнопкой Google есть пояснение для браузера без JavaScript', () => {
    const html = loginPage({
      params: PARAMS, csrfToken: 'c', emailAllowed: false, googleClientId: 'g-id', googleNonce: 'n1',
    });
    expect(html).toContain('<noscript>');
    expect(html).toContain('нужен JavaScript');
  });

  it('при сбое загрузки скрипта Google показывается сообщение', () => {
    const html = loginPage({
      params: PARAMS, csrfToken: 'c', emailAllowed: false, googleClientId: 'g-id', googleNonce: 'n1',
    });
    expect(html).toContain('onerror=');
    expect(html).toContain('Не удалось загрузить вход через Google');
  });
});

describe('п.7: ошибка формы кода доступна читалкам и возвращает фокус', () => {
  it('#code-submit-error имеет role="alert"', () => {
    const html = loginPage({ params: PARAMS, mode: 'code', email: 'a@b.co', challenge: 'h1' });
    expect(html).toMatch(/id="code-submit-error"[^>]*role="alert"/);
  });
});

describe('п.9: две одновременные регистрации клиента с одним id', () => {
  it('проигравший получает 409, а не 500', async () => {
    const deps = await makeTestDeps({ adminApiToken: 'secret', clients: [] });
    // Проверка «id свободен» занимает время: оба запроса успевают её пройти
    // до записи — как при двух одновременных запросах к базе.
    const find = deps.clients.findClient.bind(deps.clients);
    deps.clients.findClient = async (id) => {
      const found = await find(id);
      await new Promise((resolve) => setTimeout(resolve, 20));
      return found;
    };
    const app = buildServer(deps);
    const post = () =>
      app.inject({
        method: 'POST', url: '/admin/clients',
        headers: { authorization: 'Bearer secret', 'content-type': 'application/json' },
        payload: JSON.stringify({
          id: 'race-app', type: 'internal',
          redirectUris: ['https://race.example/cb'], allowedProviders: ['email'],
        }),
      });
    const statuses = (await Promise.all([post(), post()])).map((r) => r.statusCode).sort();
    expect(statuses).toEqual([201, 409]);
    await app.close();
  });
});

describe('п.10: формат code_challenge', () => {
  const bad = ['chal', 'a'.repeat(42), 'a'.repeat(129), 'a'.repeat(42) + '+', 'a'.repeat(42) + '='];
  it.each(bad)('GET /authorize с challenge %j → invalid_request редиректом', async (challenge) => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams({ ...PARAMS, code_challenge: challenge } as Record<string, string>).toString()}`,
    });
    expect(res.statusCode).toBe(302);
    const location = new URL(res.headers['location'] as string);
    expect(location.searchParams.get('error')).toBe('invalid_request');
    await app.close();
  });

  it.each(['a'.repeat(43), 'A-_z09'.repeat(10) + 'abc', 'a'.repeat(128)])('%j принимается', async (challenge) => {
    const app = buildServer(await makeTestDeps());
    const res = await app.inject({
      method: 'GET',
      url: `/authorize?${new URLSearchParams({ ...PARAMS, code_challenge: challenge } as Record<string, string>).toString()}`,
    });
    expect(res.statusCode).toBe(200);
    await app.close();
  });
});

describe('п.22: страницы входа не ходят к сторонним серверам шрифтов', () => {
  it('в общей раскладке нет ссылок на fonts.googleapis.com и fonts.gstatic.com', () => {
    const html = pageLayout('Заголовок', '<p>x</p>');
    expect(html).not.toContain('fonts.googleapis.com');
    expect(html).not.toContain('fonts.gstatic.com');
  });
});
