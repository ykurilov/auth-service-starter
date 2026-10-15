import { describe, it, expect, vi } from 'vitest';
import { loginPage } from '../../../src/adapters/http/views/login-page.js';
import { consentPage } from '../../../src/adapters/http/views/consent-page.js';
import { errorPage } from '../../../src/adapters/http/views/error-page.js';
import { logoutConfirmPage, loggedOutPage } from '../../../src/adapters/http/views/logout-page.js';
import type { OidcParams } from '../../../src/adapters/http/views/oidc-params.js';

const params: OidcParams = {
  client_id: 'app',
  redirect_uri: 'https://app.example/cb',
  code_challenge: 'chal',
  code_challenge_method: 'S256',
  scope: 'openid',
  state: 's&1',
};

describe('login-page', () => {
  it('первый шаг: только поле почты и форма identify, без пароля', () => {
    const html = loginPage({ params });
    expect(html).toContain('/authorize/identify');
    expect(html).toContain('name="email"');
    expect(html).not.toContain('name="password"');
    expect(html).toContain('name="client_id" value="app"');
  });

  it('экранирует state', () => {
    const html = loginPage({ params });
    expect(html).toContain('value="s&amp;1"');
    expect(html).not.toContain('value="s&1"');
  });

  it('режим code рендерит форму ввода кода и повторную отправку с handle попытки', () => {
    const html = loginPage({ params, mode: 'code', email: 'a@b.co', challenge: 'h<1>' });
    expect(html).toContain('name="code"');
    expect(html).toContain('/authorize/code/verify');
    expect(html).toContain('/authorize/code/request');
    expect(html).toContain('<strong>a@b.co</strong>');
    // handle — в обеих формах и экранирован; адрес в формах не передаётся.
    expect(html.match(/name="challenge" value="h&lt;1&gt;"/g)).toHaveLength(2);
    expect(html).not.toContain('name="email"');
    // Пароля больше нет ни на одном экране.
    expect(html).not.toContain('name="password"');
    expect(html).not.toContain('/authorize/register');
  });

  it('скрывает пустой блок клиентской ошибки до неуспешной отправки', () => {
    const html = loginPage({ params, mode: 'code', email: 'a@b.co' });
    expect(html).toContain('id="code-submit-error" class="alert alert-danger" hidden');
    expect(html).toContain('.auth-main .alert[hidden] { display: none !important; }');
  });

  it('заменяет POST-адрес экрана кода на безопасный GET с prompt=login для обновления страницы', () => {
    const html = loginPage({ params, mode: 'code', email: 'a@b.co' });
    const call = html.match(/window\.history\.replaceState\(null, '', ("[^"]+")\)/);
    expect(call?.[1]).toBeDefined();
    const refreshUrl = JSON.parse(call?.[1] ?? '""') as string;
    expect(refreshUrl).toContain('/authorize?client_id=app');
    expect(refreshUrl).toContain('state=s%261');
    // Обновление посреди входа ведёт к вводу почты, а не на согласие по SSO.
    expect(refreshUrl).toContain('prompt=login');
  });

  it('ссылка «с другой почтой» ведёт на /authorize с prompt=login и state', () => {
    const html = loginPage({ params, mode: 'code', email: 'a@b.co' });
    expect(html).toContain('prompt=login');
    expect(html).toContain('client_id=app');
    expect(html).toContain('Войти с другой почтой');
  });

  it('показывает текст ошибки', () => {
    const html = loginPage({ params, mode: 'code', email: 'a@b.co', error: 'Неверный или просроченный код' });
    expect(html).toContain('Неверный или просроченный код');
  });
});

describe('consent-page', () => {
  it('показывает email, форму confirm и скрытый csrf', () => {
    const html = consentPage({ params, email: 'a@b.co', csrfToken: 'tok123', expectedUser: 'u-1' });
    expect(html).toContain('a@b.co');
    expect(html).toContain('/authorize/confirm');
    expect(html).toContain('name="csrf" value="tok123"');
  });

  it('содержит кнопку входа другим аккаунтом с prompt=login', () => {
    const html = consentPage({ params, email: 'a@b.co', csrfToken: 'tok123', expectedUser: 'u-1' });
    expect(html).toContain('name="prompt" value="login"');
  });

  it('экранирует email со спецсимволом', () => {
    const html = consentPage({ params, email: 'a&<b@b.co', csrfToken: 'tok123', expectedUser: 'u-1' });
    expect(html).toContain('a&amp;&lt;b@b.co');
    expect(html).not.toContain('a&<b@b.co');
  });
});

describe('error-page', () => {
  it('рендерит title и detail', () => {
    const html = errorPage('Некорректный запрос', 'Неизвестное приложение');
    expect(html).toContain('Некорректный запрос');
    expect(html).toContain('Неизвестное приложение');
  });
});

describe('logout-confirm-page', () => {
  it('рендерит POST-форму /logout со скрытыми client_id и csrf', () => {
    const html = logoutConfirmPage({ clientId: 'app', csrfToken: 'tok123' });
    expect(html).toContain('action="/logout"');
    expect(html).toContain('name="csrf" value="tok123"');
    expect(html).toContain('name="client_id" value="app"');
  });

  it('добавляет post_logout_redirect_uri только когда он задан', () => {
    const withUri = logoutConfirmPage({
      clientId: 'app',
      postLogoutRedirectUri: 'https://app.example/after-logout',
      csrfToken: 'tok123',
    });
    expect(withUri).toContain('name="post_logout_redirect_uri" value="https://app.example/after-logout"');

    const without = logoutConfirmPage({ clientId: 'app', csrfToken: 'tok123' });
    expect(without).not.toContain('name="post_logout_redirect_uri"');
  });

  it('экранирует значения полей', () => {
    const html = logoutConfirmPage({ clientId: 'a&<b', csrfToken: 't"ok' });
    expect(html).toContain('name="client_id" value="a&amp;&lt;b"');
    expect(html).toContain('name="csrf" value="t&quot;ok"');
    expect(html).not.toContain('value="a&<b"');
  });
});

describe('logged-out-page', () => {
  it('содержит текст о выходе', () => {
    const html = loggedOutPage();
    expect(html).toContain('вышли');
  });
});

// R11: исполняем встроенный скрипт экрана ввода кода на подставном «браузере»:
// только то, что скрипт трогает (history, fetch, location и элементы по id).
describe('login-page: скрипт формы кода', () => {
  type Handler = (event: { preventDefault(): void }) => Promise<void>;

  function runCodeScript(fetchImpl: (url: string, init: unknown) => Promise<unknown>) {
    const html = loginPage({ params, mode: 'code', email: 'a@b.co', challenge: 'h1' });
    const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]!);
    const script = scripts.find((x) => x.includes('code-form'));
    if (!script) throw new Error('нет скрипта формы кода');
    let submit: Handler | undefined;
    const button = { disabled: false };
    const el = {
      'code-form': {
        action: '/authorize/code/verify',
        hidden: false,
        querySelector: () => button,
        addEventListener: (_: string, fn: Handler) => { submit = fn; },
      },
      'code-submit-error': { textContent: '', hidden: true },
      'code-resend': { hidden: false },
      'code-restart': { hidden: true },
      'code-restart-link': { href: '' },
    } as Record<string, Record<string, unknown>>;
    const replaceState = vi.fn();
    const location = { replace: vi.fn() };
    const window = { history: { replaceState }, fetch: fetchImpl, location };
    const document = { getElementById: (id: string) => el[id] ?? null };
    class FormData { *[Symbol.iterator]() { yield ['code', '1']; } }
    new Function('window', 'document', 'fetch', 'FormData', script)(window, document, fetchImpl, FormData);
    return {
      el,
      replaceState,
      location,
      submit: () => submit!({ preventDefault() {} }),
    };
  }

  function response(status: number, contentType: string, body: unknown) {
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (name: string) => (name.toLowerCase() === 'content-type' ? contentType : null) },
      json: vi.fn(async () => {
        if (!contentType.includes('application/json')) throw new SyntaxError('not json');
        return body;
      }),
    };
  }

  it('replaceState сохраняет prompt=login', () => {
    const page = runCodeScript(async () => response(200, 'application/json', {}));
    const url = new URL(page.replaceState.mock.calls[0]![2] as string, 'https://auth.example');
    expect(url.pathname).toBe('/authorize');
    expect(url.searchParams.get('prompt')).toBe('login');
  });

  it('ответ не JSON (429 страница) → понятная ошибка, json() не вызывается', async () => {
    const res = response(429, 'text/html; charset=utf-8', null);
    const page = runCodeScript(async () => res);
    await page.submit();
    expect(res.json).not.toHaveBeenCalled();
    expect(page.el['code-submit-error']!.hidden).toBe(false);
    expect(page.el['code-submit-error']!.textContent).toContain('Слишком много попыток');
  });

  it('сигнал restartTo → форма кода скрыта, показана ссылка на ввод почты', async () => {
    const page = runCodeScript(async () =>
      response(401, 'application/json; charset=utf-8', {
        error: 'Код истёк или попытки закончились — запросите новый код',
        restartTo: '/authorize?client_id=app&prompt=login',
      }),
    );
    await page.submit();
    expect(page.el['code-submit-error']!.textContent).toContain('попытки закончились');
    expect(page.el['code-form']!.hidden).toBe(true);
    expect(page.el['code-resend']!.hidden).toBe(true);
    expect(page.el['code-restart']!.hidden).toBe(false);
    expect(page.el['code-restart-link']!.href).toBe('/authorize?client_id=app&prompt=login');
    expect(page.location.replace).not.toHaveBeenCalled();
  });

  it('успех → переход по redirectTo', async () => {
    const page = runCodeScript(async () =>
      response(200, 'application/json', { redirectTo: 'https://app.example/cb?code=x' }),
    );
    await page.submit();
    expect(page.location.replace).toHaveBeenCalledWith('https://app.example/cb?code=x');
  });
});
