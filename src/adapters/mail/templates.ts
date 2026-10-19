import type { OutgoingEmail } from '../../ports/mailer.js';

// Чистые функции построения писем. Без сайд-эффектов и внешних зависимостей —
// легко тестируются и переиспользуются любым адаптером Mailer.

const ESCAPE_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ESCAPE_MAP[c] ?? c);
}

interface LayoutParts {
  title: string; // уже экранированный
  preheader: string; // уже экранированный
  intro: string; // уже экранированный
  bodyHtml: string; // произвольный (доверенный) HTML тела
  outro: string; // уже экранированный
  footer: string; // уже экранированный
}

// Email-safe layout: таблицы + инлайн-стили, контейнер max-width 480px,
// белый фон, скруглённые углы, лёгкая тень; скрытый preheader; footer.
function htmlLayout(p: LayoutParts): string {
  const font =
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
  return `<!doctype html>
<html lang="ru">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${p.title}</title>
  </head>
  <body style="margin:0; padding:0; background-color:#f3f4f6; font-family:${font};">
    <span style="display:none; max-height:0; overflow:hidden; opacity:0;">${p.preheader}</span>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f3f4f6;">
      <tr>
        <td align="center" style="padding:32px 16px;">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px; width:100%; background-color:#ffffff; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.08); overflow:hidden;">
            <tr>
              <td style="padding:32px 32px 8px 32px;">
                <h1 style="margin:0; font-size:20px; line-height:1.3; color:#111827;">${p.title}</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:0 32px; font-size:15px; line-height:1.5; color:#374151;">${p.intro}</td>
            </tr>
            <tr>
              <td style="padding:24px 32px;">${p.bodyHtml}</td>
            </tr>
            <tr>
              <td style="padding:0 32px 32px 32px; font-size:14px; line-height:1.5; color:#6b7280;">${p.outro}</td>
            </tr>
            <tr>
              <td style="padding:16px 32px; background-color:#f9fafb; border-top:1px solid #e5e7eb; font-size:12px; line-height:1.5; color:#9ca3af;">${p.footer}</td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
}

interface TextParts {
  title: string;
  intro: string;
  body: string;
  outro: string;
  footer: string;
}

function textLayout(p: TextParts): string {
  return [p.title, '', p.intro, '', p.body, '', p.outro, '', p.footer].join('\n');
}

// Вместо CTA-кнопки со ссылкой — крупный моноширинный блок с кодом, чтобы
// его было удобно списать. codeHtml уже экранирован.
function codeBlockHtml(codeHtml: string): string {
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
  <tr>
    <td align="center" style="padding:8px 0;">
      <div style="display:inline-block; padding:16px 28px; background-color:#111827; border-radius:10px; font-family:'SFMono-Regular', Menlo, Consolas, 'Liberation Mono', monospace; font-size:28px; font-weight:700; letter-spacing:6px; color:#ffffff;">${codeHtml}</div>
    </td>
  </tr>
</table>`;
}

export interface LoginCodeEmailOptions {
  to: string;
  code: string;
  ttlMinutes: number;
  appName: string;
}

export function buildLoginCodeEmail(opts: LoginCodeEmailOptions): OutgoingEmail {
  const appNameHtml = escapeHtml(opts.appName);
  const codeHtml = escapeHtml(opts.code);
  const subject = `${opts.code} — код для входа в приложение «${opts.appName}»`;
  const subjectHtml = `${codeHtml} — код для входа в приложение «${appNameHtml}»`;

  const intro = `Введите этот код, чтобы войти в ${appNameHtml}.`;
  const outro = `Код действует ${opts.ttlMinutes} минут. Если вы не пытались войти — просто проигнорируйте это письмо.`;
  const footer = `Письмо отправлено автоматически сервисом авторизации ${appNameHtml}. Отвечать на него не нужно.`;

  const html = htmlLayout({
    title: subjectHtml,
    preheader: subjectHtml,
    intro,
    bodyHtml: codeBlockHtml(codeHtml),
    outro,
    footer,
  });

  const text = textLayout({
    title: subject,
    intro: `Введите этот код, чтобы войти в ${opts.appName}.`,
    body: `Код: ${opts.code}`,
    outro: `Код действует ${opts.ttlMinutes} минут. Если вы не пытались войти — просто проигнорируйте это письмо.`,
    footer: `Письмо отправлено автоматически сервисом авторизации ${opts.appName}. Отвечать на него не нужно.`,
  });

  return { to: opts.to, subject, html, text, kind: 'login_code' };
}

// Код для привязки Google-аккаунта со сторонним адресом. Отличается от кода
// входа: верный код навсегда даёт этому Google-аккаунту вход в аккаунт
// владельца почты, поэтому письмо прямо говорит, что подтверждает код, и
// предупреждает не сообщать его никому. Имя Google-аккаунта в письмо не
// вставляем: его задаёт тот, кто входит, и оно стало бы текстом для фишинга.
export function buildGoogleLinkCodeEmail(opts: LoginCodeEmailOptions): OutgoingEmail {
  const subject = `${opts.code} — код для привязки Google-аккаунта к «${opts.appName}»`;
  const intro =
    `Кто-то входит в ${opts.appName} через Google-аккаунт и указал этот адрес почты. ` +
    'Код подтверждает, что этот Google-аккаунт ваш и его можно привязать к вашему аккаунту.';
  const consequence =
    'После привязки этот Google-аккаунт будет входить в ваш аккаунт без кода из письма.';
  const outro =
    `Код действует ${opts.ttlMinutes} минут. Никому не сообщайте код, даже «службе поддержки». ` +
    'Если вы не привязываете Google-аккаунт — просто проигнорируйте это письмо: без кода привязки не будет.';
  const footer = `Письмо отправлено автоматически сервисом авторизации ${opts.appName}. Отвечать на него не нужно.`;

  const subjectHtml = escapeHtml(subject);
  const html = htmlLayout({
    title: subjectHtml,
    preheader: subjectHtml,
    intro: `${escapeHtml(intro)}<br><br>${escapeHtml(consequence)}`,
    bodyHtml: codeBlockHtml(escapeHtml(opts.code)),
    outro: escapeHtml(outro),
    footer: escapeHtml(footer),
  });
  const text = textLayout({
    title: subject,
    intro: `${intro}\n\n${consequence}`,
    body: `Код: ${opts.code}`,
    outro,
    footer,
  });
  return { to: opts.to, subject, html, text, kind: 'google_link_code' };
}
