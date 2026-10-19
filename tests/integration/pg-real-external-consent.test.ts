import { describe, it, expect } from 'vitest';
import type { Client } from '../../src/domain/clients/client.js';
import { TEST_CSRF } from '../adapters/http/helpers.js';
import { codeOf, cookieHeader, setupPgHttp } from './pg-real-http-setup.js';

// E1 через HTTP на настоящем PostgreSQL: внешнее приложение получает код
// только после экрана согласия — и при первом входе по коду из письма, а не
// только при живой SSO-сессии. README: «подтверждение требуется при каждом
// новом входе во внешнее приложение».
const external: Client = { id: 'partner-app', type: 'external', redirectUris: ['https://partner.example/cb'], allowedProviders: ['email'] };
const internal: Client = { id: 'own-app', type: 'internal', redirectUris: ['https://own.example/cb'], allowedProviders: ['email'] };

describe.skipIf(!process.env.DATABASE_URL_TEST)('Postgres + HTTP: согласие при входе во внешнее приложение', () => {
  it('вход по коду: сначала экран согласия с названием и адресом, код — после «Продолжить»', async () => {
    const s = await setupPgHttp([external, internal]);
    try {
      const { verify, cookies } = await s.codeLogin(external, 'alice@example.test');
      // Результат входа сохранён (SSO-сессия), но кода у приложения ещё нет.
      expect(verify.statusCode).toBe(303);
      const consentUrl = String(verify.headers.location);
      expect(consentUrl.startsWith('/authorize?')).toBe(true);
      expect(consentUrl).not.toContain('code=');
      expect(cookies.sso).toBeTruthy();

      const consent = await s.app.inject({ url: consentUrl, headers: { cookie: cookieHeader(cookies) } });
      expect(consent.statusCode).toBe(200);
      expect(consent.body).toContain('partner-app');
      expect(consent.body).toContain('https://partner.example');
      expect(consent.body).toContain('alice@example.test');
      expect(consent.body).toContain('action="/authorize/confirm"');
      const expectedUser = /name="expected_user" value="([^"]+)"/.exec(consent.body)?.[1];
      expect(expectedUser).toBeTruthy();

      const confirm = await s.app.inject({ method: 'POST', url: '/authorize/confirm', headers: s.formHeaders(cookies),
        payload: s.form(external, { expected_user: expectedUser! }) });
      expect(confirm.statusCode).toBe(302);
      expect(String(confirm.headers.location).startsWith('https://partner.example/cb?')).toBe(true);
      const tokens = await s.exchange(codeOf(confirm)!, external);
      expect(tokens.statusCode).toBe(200);
      const info = await s.app.inject({ url: '/userinfo', headers: { authorization: `Bearer ${tokens.json().access_token}` } });
      expect(info.json().email).toBe('alice@example.test');
    } finally {
      await s.close();
    }
  });

  it('JS-форма кода получает адрес экрана согласия, а не callback приложения', async () => {
    const s = await setupPgHttp([external]);
    try {
      const { verify } = await s.codeLogin(external, 'bob@example.test', {}, { 'x-auth-navigation': 'replace' });
      expect(verify.statusCode).toBe(200);
      const { redirectTo } = verify.json() as { redirectTo: string };
      expect(redirectTo.startsWith('/authorize?')).toBe(true);
      expect(redirectTo).not.toContain('prompt=login');
      expect(redirectTo).not.toContain('code=');
    } finally {
      await s.close();
    }
  });

  it('отказ от согласия: код не выдан, «Войти другим аккаунтом» ведёт к вводу почты', async () => {
    const s = await setupPgHttp([external]);
    try {
      const { verify, cookies } = await s.codeLogin(external, 'carol@example.test');
      const consent = await s.app.inject({ url: String(verify.headers.location), headers: { cookie: cookieHeader(cookies) } });
      expect(consent.body).toContain('name="prompt" value="login"');
      // Подтверждение без поля пользователя (подделка, старая страница) кода не даёт.
      const forged = await s.app.inject({ method: 'POST', url: '/authorize/confirm', headers: s.formHeaders(cookies),
        payload: s.form(external, {}) });
      expect(forged.statusCode).toBe(303);
      expect(String(forged.headers.location).startsWith('/authorize?')).toBe(true);
      // Посторонний браузер без cookie не может подтвердить чужой вход.
      const stranger = await s.app.inject({ method: 'POST', url: '/authorize/confirm',
        headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `csrf=${TEST_CSRF}` },
        payload: s.form(external, { expected_user: 'any' }) });
      expect(stranger.headers.location ?? '').not.toContain('code=');
    } finally {
      await s.close();
    }
  });

  it('internal: код сразу после входа, как раньше', async () => {
    const s = await setupPgHttp([internal]);
    try {
      const { verify } = await s.codeLogin(internal, 'dave@example.test');
      expect(verify.statusCode).toBe(302);
      expect(String(verify.headers.location).startsWith('https://own.example/cb?')).toBe(true);
      expect((await s.exchange(codeOf(verify)!, internal)).statusCode).toBe(200);
      const js = await s.codeLogin(internal, 'erin@example.test', {}, { 'x-auth-navigation': 'replace' });
      expect((js.verify.json() as { redirectTo: string }).redirectTo.startsWith('https://own.example/cb?')).toBe(true);
    } finally {
      await s.close();
    }
  });
});
