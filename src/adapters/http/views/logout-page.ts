import { escapeHtml } from '../html.js';
import { pageLayout } from './page-layout.js';

export interface LogoutConfirmPageInput {
  clientId: string;
  postLogoutRedirectUri?: string;
  csrfToken: string;
}

export function logoutConfirmPage(input: LogoutConfirmPageInput): string {
  const redirectField =
    input.postLogoutRedirectUri === undefined
      ? ''
      : `<input type="hidden" name="post_logout_redirect_uri" value="${escapeHtml(input.postLogoutRedirectUri)}">`;
  const body =
    `<h1 class="h2">Выход</h1>` +
    `<p>Выйти из аккаунта во всех приложениях в этом браузере? В других браузерах и на других устройствах вход сохранится.</p>` +
    `<form method="post" action="/logout">` +
    `<input type="hidden" name="client_id" value="${escapeHtml(input.clientId)}">` +
    redirectField +
    `<input type="hidden" name="csrf" value="${escapeHtml(input.csrfToken)}">` +
    `<button type="submit" class="btn btn-danger">Выйти</button></form>`;
  return pageLayout('Выход', body);
}

export function loggedOutPage(): string {
  return pageLayout('Вы вышли', `<h1 class="h2">Вы вышли</h1><p>Вы вышли из аккаунта. Эту страницу можно закрыть.</p>`);
}

// В браузере не нашлось ни одной cookie сервиса: гасить нечего. Честно
// говорим, что вышли из этого приложения, а не из всех сессий браузера.
export function loggedOutWithoutSessionPage(): string {
  return pageLayout(
    'Вы вышли',
    `<h1 class="h2">Вы вышли</h1><p>Вы вышли из этого приложения. ` +
      `Сервис входа не нашёл в этом браузере своих cookie, поэтому другие сессии браузера, если они есть, ` +
      `истекут сами. Эту страницу можно закрыть.</p>`,
  );
}
