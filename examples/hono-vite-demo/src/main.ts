import { loadUser, loginUrl, LOGOUT_URL } from './auth-client';
import { showWithRetry } from './show-with-retry';

// Главная открыта всем. Вошедший в единый SSO (например, в соседнее
// приложение) не увидит «Войти»: loadUser() один раз тихо проверит SSO.
async function render(app: Element) {
  const user = await loadUser();
  app.innerHTML = user
    ? `<p>Вы вошли как <strong>${escape(user.name ?? user.email ?? user.id)}</strong>.</p>
       <p><a href="/cabinet.html">Личный кабинет</a> · <a href="${LOGOUT_URL}">Выйти</a></p>`
    : `<p>Вы не авторизованы. Главная страница доступна всем.</p>
       <p><a href="${loginUrl('/cabinet.html')}">Войти</a> ·
          <a href="/cabinet.html">Личный кабинет (потребует входа)</a></p>`;
}

function escape(text: string): string {
  return text.replace(/[&<>"]/g, (ch) => `&#${ch.charCodeAt(0)};`);
}

showWithRetry(document.querySelector('#app')!, render);
