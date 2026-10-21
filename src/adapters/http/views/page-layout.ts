import { escapeHtml } from '../html.js';

// Единый макет страниц сервиса в дизайн-системе LaunchLab.
// design-system.css отдаётся самим сервисом (/assets/design-system.css):
// линковать соседнюю папку воркспейса нельзя — сервис работает на удалённом
// сервере, поэтому в репозитории лежит копия (assets/design-system.css).
// Ниже — только вёрстка центрированной карточки (шелл «Centered» для форм
// входа); все цвета, радиусы и тени берутся из токенов LaunchLab.
const SHELL_STYLES = `
.auth-body { display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.auth-main { width: 100%; max-width: 400px; padding: 24px 16px; }
.auth-main .card-plain { padding: 28px; }
/* .h2 несёт верхний отступ 32px для потока текста; в карточке он лишний. */
.auth-main .h2 { margin-top: 0; }
/* В дизайн-системе .card-plain p { margin: 0 } — для наших карточек с формами
   возвращаем абзацам вертикальный ритм, иначе текст липнет к кнопкам. */
.auth-main .card-plain p { margin: 0 0 14px; }
.auth-main .card-plain p:last-child { margin-bottom: 0; }
.auth-main .btn { width: 100%; justify-content: center; }
.auth-main .alert { margin-bottom: 14px; }
.auth-main .alert[hidden] { display: none !important; }
.auth-divider { display: flex; align-items: center; gap: 10px; color: var(--text-3); font-size: 12.5px; margin: 16px 0; }
.auth-divider::before, .auth-divider::after { content: ""; flex: 1; height: 1px; background: var(--border); }
.auth-more { margin-top: 16px; text-align: center; font-size: 13px; }
.auth-more a { color: var(--accent-text); }
.auth-foot { text-align: center; margin-top: 16px; }
`;

export function pageLayout(title: string, body: string): string {
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<title>${escapeHtml(title)}</title>` +
    `<link rel="stylesheet" href="/assets/design-system.css">` +
    `<style>${SHELL_STYLES}</style></head>` +
    `<body class="auth-body"><main class="auth-main">` +
    `<div class="card-plain elevated">${body}</div>` +
    `<p class="auth-foot small muted">Сервис авторизации Гильдии</p>` +
    `</main></body></html>`;
}
