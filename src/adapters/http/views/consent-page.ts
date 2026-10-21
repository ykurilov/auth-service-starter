import { escapeHtml } from '../html.js';
import { hiddenFields, type OidcParams } from './oidc-params.js';
import { pageLayout } from './page-layout.js';

// expectedUser — id пользователя SSO-сессии, для которого показан экран.
// Уходит скрытым полем: если к нажатию в соседней вкладке вошли другим
// аккаунтом, подтверждение не выдаст код другому человеку.
export interface ConsentPageInput {
  params: OidcParams;
  email: string;
  csrfToken: string;
  expectedUser: string;
}

// Какому приложению выдаётся вход: origin его redirect_uri (проверен по
// белому списку клиента до показа экрана).
function appOrigin(redirectUri: string): string {
  try {
    return new URL(redirectUri).origin;
  } catch {
    return redirectUri;
  }
}

export function consentPage(input: ConsentPageInput): string {
  const hf = hiddenFields(input.params);
  const email = escapeHtml(input.email);
  const csrf = escapeHtml(input.csrfToken);
  const origin = escapeHtml(appOrigin(input.params.redirect_uri));
  // Название — идентификатор клиента, под которым его зарегистрировали.
  const name = escapeHtml(input.params.client_id);
  const body =
    `<h1 class="h2">Вход в приложение</h1>` +
    `<p>Приложение <strong>${name}</strong> (<strong>${origin}</strong>) просит войти от вашего имени.</p>` +
    `<p>Вы вошли как <strong>${email}</strong>.</p>` +
    `<form method="post" action="/authorize/confirm">${hf}` +
    `<input type="hidden" name="csrf" value="${csrf}">` +
    `<input type="hidden" name="expected_user" value="${escapeHtml(input.expectedUser)}">` +
    `<button type="submit" class="btn btn-primary">Продолжить как ${email}</button></form>` +
    `<div class="auth-divider">или</div>` +
    `<form method="get" action="/authorize">${hf}` +
    `<input type="hidden" name="prompt" value="login">` +
    `<button type="submit" class="btn">Войти другим аккаунтом</button></form>` +
    `<form method="post" action="/authorize/deny">${hf}` +
    `<input type="hidden" name="csrf" value="${csrf}">` +
    `<button type="submit" class="btn">Отказаться</button></form>`;
  return pageLayout('Подтверждение входа', body);
}
