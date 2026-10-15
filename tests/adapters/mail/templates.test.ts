import { describe, it, expect } from 'vitest';
import { escapeHtml, buildLoginCodeEmail, buildGoogleLinkCodeEmail } from '../../../src/adapters/mail/templates.js';

describe('escapeHtml', () => {
  it('экранирует все 5 спецсимволов', () => {
    expect(escapeHtml('& < > " \'')).toBe('&amp; &lt; &gt; &quot; &#39;');
  });

  it('обычный текст не меняет', () => {
    expect(escapeHtml('Auth Service 123')).toBe('Auth Service 123');
  });
});

describe('buildLoginCodeEmail', () => {
  const opts = { to: 'user@x.com', code: '123456', ttlMinutes: 15, appName: 'Auth Service' };

  it('код стоит первым в теме и превью письма', () => {
    const email = buildLoginCodeEmail(opts);
    expect(email.subject).toBe('123456 — код для входа в приложение «Auth Service»');
    expect(email.text.startsWith('123456 — код для входа в приложение «Auth Service»')).toBe(true);
    expect(email.html).toContain('>123456 — код для входа в приложение «Auth Service»</span>');
  });

  it('to пробрасывается как есть', () => {
    expect(buildLoginCodeEmail(opts).to).toBe('user@x.com');
  });

  it('html содержит код и имя приложения', () => {
    const email = buildLoginCodeEmail(opts);
    expect(email.html).toBeDefined();
    expect(email.html).toContain('123456');
    expect(email.html).toContain('Auth Service');
  });

  it('text содержит код и имя приложения', () => {
    const email = buildLoginCodeEmail(opts);
    expect(email.text).toContain('123456');
    expect(email.text).toContain('Auth Service');
    expect(email.text).toContain('Код: 123456');
  });

  it('спецсимволы в code и appName экранируются в html (нет сырого <)', () => {
    const email = buildLoginCodeEmail({
      to: 'user@x.com',
      code: '<script>',
      ttlMinutes: 15,
      appName: 'Acme & <Co>',
    });
    expect(email.html).not.toContain('<script>');
    expect(email.html).toContain('&lt;script&gt;');
    expect(email.html).toContain('Acme &amp; &lt;Co&gt;');
  });
});

describe('buildGoogleLinkCodeEmail (R20)', () => {
  const opts = { to: 'boss@corp.example', code: '123456', ttlMinutes: 15, appName: 'Auth Service', googleName: 'Иван <script>' };

  it('тема и текст говорят о привязке Google-аккаунта, а не об обычном входе', () => {
    const email = buildGoogleLinkCodeEmail(opts);
    expect(email.subject).toBe('123456 — код для привязки Google-аккаунта к «Auth Service»');
    expect(email.subject).not.toBe(buildLoginCodeEmail(opts).subject);
    expect(email.text).toContain('привяз');
    expect(email.text).toContain('Google');
    expect(email.text).toContain('Иван <script>');
    expect(email.text).toContain('без кода');
    expect(email.text).toContain('Никому не сообщайте');
    expect(email.text).toContain('123456');
  });

  it('html содержит код и экранирует имя из Google', () => {
    const email = buildGoogleLinkCodeEmail(opts);
    expect(email.html).toContain('123456');
    expect(email.html).toContain('Иван &lt;script&gt;');
    expect(email.html).not.toContain('<script>');
  });

  it('без имени в Google письмо тоже понятное', () => {
    const { googleName: _, ...rest } = opts;
    const email = buildGoogleLinkCodeEmail(rest);
    expect(email.text).toContain('Google-аккаунт');
    expect(email.text).not.toContain('undefined');
  });
});
