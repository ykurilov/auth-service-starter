import { escapeHtml } from '../html.js';
import { hiddenFields, type OidcParams } from './oidc-params.js';
import { pageLayout } from './page-layout.js';

export interface ConsentPageInput { params: OidcParams; email: string; csrfToken: string; }

export function consentPage(input: ConsentPageInput): string {
  const hf = hiddenFields(input.params);
  const email = escapeHtml(input.email);
  const csrf = escapeHtml(input.csrfToken);
  const body =
    `<h1 class="h2">Вход в приложение</h1>` +
    `<p>Вы вошли как <strong>${email}</strong>.</p>` +
    `<form method="post" action="/authorize/confirm">${hf}` +
    `<input type="hidden" name="csrf" value="${csrf}">` +
    `<button type="submit" class="btn btn-primary">Продолжить как ${email}</button></form>` +
    `<div class="auth-divider">или</div>` +
    `<form method="get" action="/authorize">${hf}` +
    `<input type="hidden" name="prompt" value="login">` +
    `<button type="submit" class="btn">Войти другим аккаунтом</button></form>`;
  return pageLayout('Подтверждение входа', body);
}
