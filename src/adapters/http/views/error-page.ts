import { escapeHtml } from '../html.js';
import { pageLayout } from './page-layout.js';

export function errorPage(title: string, detail: string): string {
  return pageLayout(
    title,
    `<h1 class="h2">${escapeHtml(title)}</h1><div class="alert alert-danger">${escapeHtml(detail)}</div>`,
  );
}
