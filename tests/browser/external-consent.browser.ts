import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { chromium, type Browser } from 'playwright';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CHALLENGE } from '../adapters/http/helpers.js';

// Вход по коду во внешнее приложение в настоящем Chromium: JS-форма кода
// уводит на экран согласия с названием и адресом приложения, и только после
// «Продолжить как …» браузер приходит в callback с кодом.

let browser: Browser;
let callback: http.Server;
let service: FastifyInstance;

beforeAll(async () => {
  browser = await chromium.launch();
});

afterAll(async () => {
  await browser?.close();
  callback?.close();
  await service?.close();
});

it('вход по коду во внешнее приложение: экран согласия, затем callback с кодом', async () => {
  const callbackHits: string[] = [];
  callback = http.createServer((req, res) => {
    callbackHits.push(req.url ?? '');
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Приложение: вход выполнен');
  });
  const appUrl = await new Promise<string>((resolve) =>
    callback.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(callback.address() as AddressInfo).port}`)),
  );
  const deps = await makeTestDeps({
    clients: [{ id: 'partner-app', type: 'external', redirectUris: [`${appUrl}/cb`], allowedProviders: ['email'] }],
  });
  service = buildServer(deps);
  const authUrl = await service.listen({ port: 0, host: '127.0.0.1' });
  // Формы сверяют Origin с адресом сервиса.
  deps.config.issuerUrl = authUrl;

  const page = await browser.newPage();
  const query = new URLSearchParams({
    client_id: 'partner-app', redirect_uri: `${appUrl}/cb`, response_type: 'code', scope: 'openid email',
    code_challenge: TEST_CHALLENGE, code_challenge_method: 'S256', state: 'browser-state',
  });
  await page.goto(`${authUrl}/authorize?${query}`);
  await page.getByLabel(/почт/i).fill('alice@example.test');
  await page.getByRole('button', { name: 'Получить код' }).click();
  await page.getByLabel(/код/i).fill('CODE55');
  await page.getByRole('button', { name: /Войти/ }).click();

  await page.getByRole('button', { name: /Продолжить как/ }).waitFor({ timeout: 5000 });
  expect(new URL(page.url()).origin).toBe(authUrl);
  const text = await page.textContent('body');
  expect(text).toContain('partner-app');
  expect(text).toContain(appUrl);
  expect(text).toContain('alice@example.test');
  expect(callbackHits).toEqual([]);

  await page.getByRole('button', { name: /Продолжить как/ }).click();
  await page.waitForURL(`${appUrl}/cb**`, { timeout: 5000 });
  const landed = new URL(page.url());
  expect(landed.searchParams.get('code')).toBeTruthy();
  expect(landed.searchParams.get('state')).toBe('browser-state');
  expect(callbackHits).toHaveLength(1);
});
