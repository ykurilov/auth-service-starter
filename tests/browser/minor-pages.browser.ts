import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { chromium, type Browser } from 'playwright';
import type { FastifyInstance } from 'fastify';
import type { Client } from '../../src/domain/clients/client.js';
import { buildServer } from '../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CHALLENGE } from '../adapters/http/helpers.js';

// Мелкие страницы входа в настоящем Chromium: отказ на экране согласия,
// ошибка неверного кода, ссылка назад после истёкшей формы, выход без
// cookie, отсутствие обращений к сторонним шрифтам.

const servers: http.Server[] = [];
const services: FastifyInstance[] = [];
let browser: Browser;

function listen(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)),
  );
}

async function startService(clients: Client[]) {
  const deps = await makeTestDeps({ clients });
  const service = buildServer(deps);
  services.push(service);
  const authUrl = await service.listen({ port: 0, host: '127.0.0.1' });
  deps.config.issuerUrl = authUrl; // формы сверяют Origin с адресом сервиса
  return authUrl;
}

const authorizeUrl = (authUrl: string, clientId: string, appUrl: string) =>
  `${authUrl}/authorize?${new URLSearchParams({
    client_id: clientId, redirect_uri: `${appUrl}/cb`, response_type: 'code', scope: 'openid email',
    code_challenge: TEST_CHALLENGE, code_challenge_method: 'S256', state: 'st-minor',
  })}`;

beforeAll(async () => {
  browser = await chromium.launch();
});

afterAll(async () => {
  await browser?.close();
  for (const server of servers) server.close();
  for (const service of services) await service.close();
});

it('отказ на экране согласия возвращает в приложение с access_denied и state', async () => {
  const appUrl = await listen((_req, res) => { res.writeHead(200); res.end('Приложение'); });
  const authUrl = await startService([
    { id: 'partner', type: 'external', redirectUris: [`${appUrl}/cb`], allowedProviders: ['email'] },
  ]);
  const page = await browser.newPage();
  await page.goto(authorizeUrl(authUrl, 'partner', appUrl));
  await page.getByLabel(/почт/i).fill('deny@example.test');
  await page.getByRole('button', { name: 'Получить код' }).click();
  await page.getByLabel(/код/i).fill('CODE55');
  await page.getByRole('button', { name: /Войти/ }).click();
  await page.getByRole('button', { name: /Продолжить как/ }).waitFor({ timeout: 5000 });

  await page.getByRole('button', { name: 'Отказаться' }).click();
  await page.waitForURL(`${appUrl}/cb**`, { timeout: 5000 });
  const landed = new URL(page.url());
  expect(landed.searchParams.get('error')).toBe('access_denied');
  expect(landed.searchParams.get('state')).toBe('st-minor');
  expect(landed.searchParams.get('code')).toBeNull();
});

it('неверный код: ошибка видна как предупреждение, фокус вернулся в поле кода', async () => {
  const appUrl = await listen((_req, res) => { res.writeHead(200); res.end('Приложение'); });
  const authUrl = await startService([
    { id: 'int', type: 'internal', redirectUris: [`${appUrl}/cb`], allowedProviders: ['email'] },
  ]);
  const requested: string[] = [];
  const page = await browser.newPage();
  page.on('request', (req) => requested.push(new URL(req.url()).hostname));
  await page.goto(authorizeUrl(authUrl, 'int', appUrl));
  await page.getByLabel(/почт/i).fill('wrong@example.test');
  await page.getByRole('button', { name: 'Получить код' }).click();
  await page.getByLabel(/код/i).fill('WRONG1');
  await page.getByRole('button', { name: /Войти/ }).click();

  const alert = page.getByRole('alert');
  await alert.waitFor({ timeout: 5000 });
  expect((await alert.textContent())?.trim().length).toBeGreaterThan(0);
  expect(await page.evaluate(() => document.activeElement?.getAttribute('name'))).toBe('code');
  // Без шрифтов Google и прочих сторонних серверов.
  expect(requested.filter((host) => host !== '127.0.0.1')).toEqual([]);
});

it('форма входа с потерянной cookie: страница отказа ведёт обратно ко входу', async () => {
  const appUrl = await listen((_req, res) => { res.writeHead(200); res.end('Приложение'); });
  const authUrl = await startService([
    { id: 'int', type: 'internal', redirectUris: [`${appUrl}/cb`], allowedProviders: ['email'] },
  ]);
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(authorizeUrl(authUrl, 'int', appUrl));
  await page.getByLabel(/почт/i).fill('stale@example.test');
  await context.clearCookies();
  await page.getByRole('button', { name: 'Получить код' }).click();

  const back = page.getByRole('link', { name: 'Вернуться ко входу' });
  await back.waitFor({ timeout: 5000 });
  await back.click();
  await page.getByLabel(/почт/i).waitFor({ timeout: 5000 });
  expect(new URL(page.url()).pathname).toBe('/authorize');
  expect(new URL(page.url()).searchParams.get('client_id')).toBe('int');
});

it('выход без cookie говорит про это приложение, а не про все сессии', async () => {
  const appUrl = await listen((_req, res) => { res.writeHead(200); res.end('Приложение'); });
  const authUrl = await startService([
    { id: 'int', type: 'internal', redirectUris: [`${appUrl}/cb`], postLogoutRedirectUris: [`${appUrl}/`], allowedProviders: ['email'] },
  ]);
  const page = await browser.newPage();
  await page.goto(`${authUrl}/logout?client_id=int`);
  await page.getByRole('button', { name: /Выйти/ }).click();
  await page.getByText('из этого приложения').waitFor({ timeout: 5000 });
  expect(await page.textContent('body')).toContain('истекут сами');
});
