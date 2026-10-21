import { escapeHtml } from '../html.js';
import { authorizeUrl, hiddenFields, type OidcParams } from './oidc-params.js';
import { pageLayout } from './page-layout.js';

// Identifier-first вход: сначала только почта, затем одноразовый код из письма
// на неё. Это единственный способ входа по почте — пароля больше нет.
export interface LoginPageInput {
  params: OidcParams;
  mode?: 'identify' | 'code';
  email?: string;
  // handle попытки входа по коду (режим code): скрытое поле обеих форм экрана
  // ввода — проверки и переотправки. Адрес для сервера в формах не передаётся:
  // попытка знает его сама. Скрытое поле email_hint несёт адрес лишь для
  // подстановки в поле почты, если попытка к отправке уже исчезла.
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
  // Google разрешён и настроен, но лимит выпуска nonce исчерпан: вместо кнопки
  // — пояснение с временем ожидания («через 15 мин»).
  googleUnavailableFor?: string;
  // Клиенту разрешён вход по почте. false — формы почты нет (только Google).
  emailAllowed?: boolean;
}

const field = (label: string, input: string): string =>
  `<label class="field"><span class="label">${label}</span>${input}</label>`;

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
function googleSignIn(clientId: string, nonce: string, hf: string, csrfField: string, divider: boolean): string {
  const cid = escapeHtml(clientId);
  const gnonce = escapeHtml(nonce);
  return `${divider ? '<div class="auth-divider">или</div>' : ''}
    <form id="google-form" method="post" action="/authorize/google">
      ${hf}
      ${csrfField}
      <input type="hidden" name="credential">
    </form>
    <div id="google-btn"></div>
    <noscript><p class="muted">Для входа через Google нужен JavaScript. Включите его в браузере${divider ? ' или войдите по почте' : ''}.</p></noscript>
    <p id="google-unavailable" class="muted" hidden>Не удалось загрузить вход через Google. Проверьте, что скрипт Google не заблокирован расширением или сетью${divider ? ', или войдите по почте' : ''}.</p>
    <script>
      function onGoogleLibError() {
        document.getElementById('google-unavailable').hidden = false;
      }
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
    <script src="https://accounts.google.com/gsi/client" onload="onGoogleLibLoad()" onerror="onGoogleLibError()" async defer></script>`;
}

// Успешный вход заменяет текущую запись формы в истории. Нативный POST остаётся
// fallback без JavaScript; при ошибке код можно исправить на той же странице.
// Запись истории ведёт на экран ввода почты (prompt=login): обновление
// страницы посреди входа не уводит на экран согласия по SSO-cookie.
// Ответ не JSON (страница 429 или ошибки формы) — понятная ошибка вместо
// сбоя разбора. restartTo — попытка исчерпана: форма кода больше не нужна,
// показываем переход к вводу почты.
function codeFormNavigation(p: OidcParams): string {
  const safeRefreshUrl = JSON.stringify(restartUrl(p));
  return `<script>
    (function () {
      if (window.history && window.history.replaceState) {
        window.history.replaceState(null, '', ${safeRefreshUrl});
      }
      var form = document.getElementById('code-form');
      var error = document.getElementById('code-submit-error');
      if (!form || !error || !window.fetch) return;
      function showError(text) {
        error.textContent = text;
        error.hidden = false;
      }
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
          var type = response.headers.get('content-type') || '';
          if (type.indexOf('application/json') === -1) {
            var wait = Number(response.headers.get('retry-after'));
            showError(response.status === 429
              ? (wait > 0
                ? 'Слишком много попыток — повторите через ' + Math.ceil(wait / 60) + ' мин'
                : 'Слишком много попыток — подождите немного и попробуйте ещё раз')
              : 'Не удалось войти, обновите страницу и попробуйте ещё раз');
            return;
          }
          var data = await response.json();
          if (typeof data.restartTo === 'string') {
            showError(data.error || 'Попытки закончились — начните вход заново');
            form.hidden = true;
            var resend = document.getElementById('code-resend');
            if (resend) resend.hidden = true;
            var restart = document.getElementById('code-restart');
            var link = document.getElementById('code-restart-link');
            if (link) link.href = data.restartTo;
            if (restart) restart.hidden = false;
            return;
          }
          if (!response.ok || typeof data.redirectTo !== 'string') {
            showError(data.error || 'Не удалось войти, попробуйте ещё раз');
            return;
          }
          window.location.replace(data.redirectTo);
        } catch (_) {
          showError('Не удалось войти, проверьте соединение и попробуйте ещё раз');
        } finally {
          if (button) button.disabled = false;
          // После отправки фокус остаётся на отключённой кнопке и уходит в BODY:
          // возвращаем его в поле кода, чтобы можно было сразу поправить код.
          var codeInput = form.elements && form.elements.code;
          if (codeInput && !form.hidden && codeInput.focus) codeInput.focus();
        }
      });
    })();
  </script>`;
}

// Обычные формы (почта, переотправка) уходят нативным POST: кнопка
// блокируется после первого нажатия, чтобы двойной клик или Enter не
// отправили второй запрос, пока почтовый провайдер отвечает. Блок снимают
// страница, возвращённая кнопкой «Назад» из кеша браузера, и пауза дольше
// ожидания провайдера (на случай остановленной загрузки).
const SUBMIT_ONCE = `<script>
    (function () {
      var forms = document.querySelectorAll('form[data-submit-once]');
      function unlock(form) {
        delete form.dataset.sent;
        var list = form.querySelectorAll('button[type="submit"]');
        for (var j = 0; j < list.length; j++) list[j].disabled = false;
      }
      for (var i = 0; i < forms.length; i++) {
        forms[i].addEventListener('submit', function (event) {
          var form = this;
          if (form.dataset.sent) { event.preventDefault(); return; }
          form.dataset.sent = '1';
          var list = form.querySelectorAll('button[type="submit"]');
          for (var j = 0; j < list.length; j++) list[j].disabled = true;
          setTimeout(function () { unlock(form); }, 15000);
        });
      }
      window.addEventListener('pageshow', function () {
        for (var i = 0; i < forms.length; i++) unlock(forms[i]);
      });
    })();
  </script>`;

export function loginPage(input: LoginPageInput): string {
  const p = input.params;
  const hf = hiddenFields(p);
  const csrfField = `<input type="hidden" name="csrf" value="${escapeHtml(input.csrfToken ?? '')}">`;
  const email = input.email ? escapeHtml(input.email) : '';
  const err = input.error ? `<div class="alert alert-danger">${escapeHtml(input.error)}</div>` : '';
  const notice = input.notice ? `<div class="alert alert-success">${escapeHtml(input.notice)}</div>` : '';
  const mode = input.mode ?? 'identify';
  const challengeField =
    `<input type="hidden" name="challenge" value="${escapeHtml(input.challenge ?? '')}">` +
    `<input type="hidden" name="email_hint" value="${email}">`;

  const restart = `<p class="auth-more"><a href="${escapeHtml(restartUrl(p))}">Войти с другой почтой</a></p>`;

  let title = 'Вход';
  let body: string;

  switch (mode) {
    case 'code':
      title = 'Код из письма';
      body = `<h1 class="h2">Код из письма</h1>${err}${notice}
        <div id="code-submit-error" class="alert alert-danger" role="alert" hidden></div>
        <p class="muted">Отправили код на <strong>${email}</strong>.</p>
        <form id="code-form" method="post" action="/authorize/code/verify">
          ${hf}
          ${csrfField}
          ${challengeField}
          ${field('Код из письма', `<input class="input" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus required>`)}
          <button type="submit" class="btn btn-primary">Войти</button>
        </form>
        <p id="code-restart" hidden><a id="code-restart-link" class="btn btn-primary" href="${escapeHtml(restartUrl(p))}">Ввести почту заново</a></p>
        <div id="code-resend">
          <div class="auth-divider">не пришёл?</div>
          <form method="post" action="/authorize/code/request" data-submit-once>
            ${hf}
            ${csrfField}
            ${challengeField}
            <button type="submit" class="btn">Отправить код ещё раз</button>
          </form>
        </div>
        ${restart}
        ${codeFormNavigation(p)}
        ${SUBMIT_ONCE}`;
      break;
    default: {
      const emailForm = `<p class="muted">Введите почту — пришлём на неё код для входа.</p>
        <form method="post" action="/authorize/identify" data-submit-once>
          ${hf}
          ${csrfField}
          ${field('Почта', `<input class="input" type="email" name="email" value="${email}" autocomplete="email" autofocus required>`)}
          <button type="submit" class="btn btn-primary">Получить код</button>
        </form>`;
      const emailAllowed = input.emailAllowed ?? true;
      let google = '';
      if (input.googleClientId) {
        google = googleSignIn(input.googleClientId, input.googleNonce ?? '', hf, csrfField, emailAllowed);
      } else if (input.googleUnavailableFor) {
        google = `<p class="muted">Вход через Google временно недоступен: слишком много входов из вашей сети. Попробуйте ${escapeHtml(input.googleUnavailableFor)}${emailAllowed ? ' или войдите по почте' : ''}.</p>`;
      }
      const none = !emailAllowed && !google
        ? '<div class="alert alert-danger">Для этого приложения сейчас нет доступного способа входа.</div>'
        : '';
      body = `<h1 class="h2">Вход</h1>${err}${notice}${none}
        ${emailAllowed ? `${emailForm}${SUBMIT_ONCE}` : ''}
        ${google}`;
    }
  }

  return pageLayout(title, body);
}
