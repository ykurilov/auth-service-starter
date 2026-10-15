import { describe, it, expect } from 'vitest';
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

  it('заменяет POST-адрес экрана кода на безопасный GET для обновления страницы', () => {
    const html = loginPage({ params, mode: 'code', email: 'a@b.co' });
    const call = html.match(/window\.history\.replaceState\(null, '', ("[^"]+")\)/);
    expect(call?.[1]).toBeDefined();
    const refreshUrl = JSON.parse(call?.[1] ?? '""') as string;
    expect(refreshUrl).toContain('/authorize?client_id=app');
    expect(refreshUrl).toContain('state=s%261');
    expect(refreshUrl).not.toContain('prompt=login');
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
    const html = consentPage({ params, email: 'a@b.co', csrfToken: 'tok123' });
    expect(html).toContain('a@b.co');
    expect(html).toContain('/authorize/confirm');
    expect(html).toContain('name="csrf" value="tok123"');
  });

  it('содержит кнопку входа другим аккаунтом с prompt=login', () => {
    const html = consentPage({ params, email: 'a@b.co', csrfToken: 'tok123' });
    expect(html).toContain('name="prompt" value="login"');
  });

  it('экранирует email со спецсимволом', () => {
    const html = consentPage({ params, email: 'a&<b@b.co', csrfToken: 'tok123' });
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
