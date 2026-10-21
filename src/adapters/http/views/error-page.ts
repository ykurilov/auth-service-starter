import { escapeHtml } from '../html.js';
import { pageLayout } from './page-layout.js';

// Ссылка возврата под текстом ошибки: куда пойти, чтобы попробовать снова.
export interface ErrorPageBack {
  href: string;
  label: string;
}

export function errorPage(title: string, detail: string, back?: ErrorPageBack): string {
  const backLink = back
    ? `<p class="auth-more"><a class="btn" href="${escapeHtml(back.href)}">${escapeHtml(back.label)}</a></p>`
    : '';
  return pageLayout(
    title,
    `<h1 class="h2">${escapeHtml(title)}</h1><div class="alert alert-danger">${escapeHtml(detail)}</div>${backLink}`,
  );
}
