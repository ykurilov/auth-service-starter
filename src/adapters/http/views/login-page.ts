import { escapeHtml } from '../html.js';
import { hiddenFields, type OidcParams } from './oidc-params.js';
import { pageLayout } from './page-layout.js';

// Identifier-first вход: сначала только почта, затем одноразовый код из письма
// на неё. Это единственный способ входа по почте — пароля больше нет.
export interface LoginPageInput {
  params: OidcParams;
  mode?: 'identify' | 'code';
  email?: string;
  // handle попытки входа по коду (режим code): скрытое поле обеих форм экрана
  // ввода — проверки и переотправки. Адрес в формах больше не передаётся:
  // попытка знает его сама.
  challenge?: string;
  error?: string;
  notice?: string;
  // CSRF-токен: одно значение на всю identifier-first цепочку, приходит из
  // csrf-cookie и дублируется скрытым полем в каждой форме (double-submit).
  csrfToken?: string;
  // Кнопка «Войти через Google» на первом шаге. Задаётся только когда Google
  // настроен (GOOGLE_CLIENT_ID) и разрешён клиенту (allowedProviders).
  googleClientId?: string;
  // Одноразовый nonce для GIS: сервер выпускает его вместе с кнопкой и сверяет
  // с claim nonce id_token (анти-replay). Присутствует только с googleClientId.
  googleNonce?: string;
}

const field = (label: string, input: string): string =>
  `<label class="field"><span class="label">${label}</span>${input}</label>`;

function authorizeUrl(p: OidcParams, promptLogin = false): string {
  const q = new URLSearchParams();
  q.set('client_id', p.client_id);
  q.set('redirect_uri', p.redirect_uri);
  q.set('code_challenge', p.code_challenge);
  q.set('code_challenge_method', p.code_challenge_method);
  q.set('scope', p.scope);
  if (p.state !== undefined) q.set('state', p.state);
  if (p.nonce !== undefined) q.set('nonce', p.nonce);
  if (promptLogin) q.set('prompt', 'login');
  return `/authorize?${q.toString()}`;
}

// Ссылка «Войти с другой почтой»: возвращает на первый шаг, сохранив
// OIDC-параметры. prompt=login не даёт SSO-куке увести на экран согласия.
function restartUrl(p: OidcParams): string {
  return authorizeUrl(p, true);
}

// Google Identity Services: виджет Google получает ID Token на странице,
// колбэк кладёт его в скрытую форму и отправляет на /authorize/google вместе
// с OIDC-параметрами. Секретов на странице нет — только публичный client id.
// Кнопку рендерим программно (renderButton), а не data-атрибутами: только так
// ей можно задать ширину по факту, вровень с остальными кнопками формы.
function googleSignIn(clientId: string, nonce: string, hf: string, csrfField: string): string {
  const cid = escapeHtml(clientId);
  const gnonce = escapeHtml(nonce);
  return `<div class="auth-divider">или</div>
    <form id="google-form" method="post" action="/authorize/google">
      ${hf}
      ${csrfField}
      <input type="hidden" name="credential">
    </form>
    <div id="google-btn"></div>
    <script>
      function onGoogleLibLoad() {
        google.accounts.id.initialize({
          client_id: '${cid}',
          nonce: '${gnonce}',
          callback: function (r) {
            var f = document.getElementById('google-form');
            f.elements.credential.value = r.credential;
            f.submit();
          }
        });
        var el = document.getElementById('google-btn');
        google.accounts.id.renderButton(el, {
          type: 'standard', theme: 'outline', size: 'large',
          text: 'signin_with', locale: 'ru',
          width: Math.min(el.offsetWidth, 400)
        });
      }
    </script>
    <script src="https://accounts.google.com/gsi/client" onload="onGoogleLibLoad()" async defer></script>`;
}

// Успешный вход заменяет текущую запись формы в истории. Нативный POST остаётся
// fallback без JavaScript; при ошибке код можно исправить на той же странице.
function codeFormNavigation(p: OidcParams): string {
  const safeRefreshUrl = JSON.stringify(authorizeUrl(p));
  return `<script>
    (function () {
      if (window.history && window.history.replaceState) {
        window.history.replaceState(null, '', ${safeRefreshUrl});
      }
      var form = document.getElementById('code-form');
      var error = document.getElementById('code-submit-error');
      if (!form || !error || !window.fetch) return;
      form.addEventListener('submit', async function (event) {
        event.preventDefault();
        var button = form.querySelector('button[type="submit"]');
        if (button) button.disabled = true;
        error.hidden = true;
        try {
          var response = await fetch(form.action, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
              'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
              'x-auth-navigation': 'replace'
            },
            body: new URLSearchParams(new FormData(form)).toString()
          });
          var data = await response.json();
          if (!response.ok || typeof data.redirectTo !== 'string') {
            error.textContent = data.error || 'Не удалось войти, попробуйте ещё раз';
            error.hidden = false;
            return;
          }
          window.location.replace(data.redirectTo);
        } catch (_) {
          error.textContent = 'Не удалось войти, проверьте соединение и попробуйте ещё раз';
          error.hidden = false;
        } finally {
          if (button) button.disabled = false;
        }
      });
    })();
  </script>`;
}

export function loginPage(input: LoginPageInput): string {
  const p = input.params;
  const hf = hiddenFields(p);
  const csrfField = `<input type="hidden" name="csrf" value="${escapeHtml(input.csrfToken ?? '')}">`;
  const email = input.email ? escapeHtml(input.email) : '';
  const err = input.error ? `<div class="alert alert-danger">${escapeHtml(input.error)}</div>` : '';
  const notice = input.notice ? `<div class="alert alert-success">${escapeHtml(input.notice)}</div>` : '';
  const mode = input.mode ?? 'identify';
  const challengeField = `<input type="hidden" name="challenge" value="${escapeHtml(input.challenge ?? '')}">`;

  const restart = `<p class="auth-more"><a href="${escapeHtml(restartUrl(p))}">Войти с другой почтой</a></p>`;

  let title = 'Вход';
  let body: string;

  switch (mode) {
    case 'code':
      title = 'Код из письма';
      body = `<h1 class="h2">Код из письма</h1>${err}${notice}
        <div id="code-submit-error" class="alert alert-danger" hidden></div>
        <p class="muted">Отправили код на <strong>${email}</strong>.</p>
        <form id="code-form" method="post" action="/authorize/code/verify">
          ${hf}
          ${csrfField}
          ${challengeField}
          ${field('Код из письма', `<input class="input" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus required>`)}
          <button type="submit" class="btn btn-primary">Войти</button>
        </form>
        <div class="auth-divider">не пришёл?</div>
        <form method="post" action="/authorize/code/request">
          ${hf}
          ${csrfField}
          ${challengeField}
          <button type="submit" class="btn">Отправить код ещё раз</button>
        </form>
        ${restart}
        ${codeFormNavigation(p)}`;
      break;
    default:
      body = `<h1 class="h2">Вход</h1>${err}${notice}
        <p class="muted">Введите почту — пришлём на неё код для входа.</p>
        <form method="post" action="/authorize/identify">
          ${hf}
          ${csrfField}
          ${field('Почта', `<input class="input" type="email" name="email" value="${email}" autocomplete="email" autofocus required>`)}
          <button type="submit" class="btn btn-primary">Получить код</button>
        </form>
        ${input.googleClientId ? googleSignIn(input.googleClientId, input.googleNonce ?? '', hf, csrfField) : ''}`;
  }

  return pageLayout(title, body);
}
