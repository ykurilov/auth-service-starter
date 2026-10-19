import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../src/adapters/http/server.js';
import { makeTestDeps, TEST_CHALLENGE, TEST_VERIFIER } from '../adapters/http/helpers.js';

// Два браузера одного пользователя (два контекста Chromium — свои cookie у
// каждого): «Выйти» в одном завершает вход во всех приложениях этого
// браузера и не трогает другой.

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

it('выход в одном браузере не выкидывает того же пользователя в другом', async () => {
  callback = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Приложение');
  });
  const appUrl = await new Promise<string>((resolve) =>
    callback.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(callback.address() as AddressInfo).port}`)),
  );
  const deps = await makeTestDeps({
    clients: [{ id: 'int', type: 'internal', redirectUris: [`${appUrl}/cb`], allowedProviders: ['email'] }],
  });
  service = buildServer(deps);
  const authUrl = await service.listen({ port: 0, host: '127.0.0.1' });
  // Формы сверяют Origin с адресом сервиса.
  deps.config.issuerUrl = authUrl;

  const authorizeUrl = (extra: Record<string, string> = {}) => `${authUrl}/authorize?${new URLSearchParams({
    client_id: 'int', redirect_uri: `${appUrl}/cb`, response_type: 'code', scope: 'openid email',
    code_challenge: TEST_CHALLENGE, code_challenge_method: 'S256', state: 'st', ...extra,
  })}`;
  const token = async (body: Record<string, string>) =>
    fetch(`${authUrl}/oauth/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body),
    });
  const refresh = async (refreshToken: string) =>
    (await token({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: 'int' })).status;

  async function signIn(context: BrowserContext): Promise<string> {
    const page = await context.newPage();
    await page.goto(authorizeUrl());
    await page.getByLabel(/почт/i).fill('same@example.test');
    await page.getByRole('button', { name: 'Получить код' }).click();
    await page.getByLabel(/код/i).fill('CODE55');
    await page.getByRole('button', { name: /Войти/ }).click();
    await page.waitForURL(`${appUrl}/cb**`, { timeout: 5000 });
    const code = new URL(page.url()).searchParams.get('code')!;
    const issued = await token({
      grant_type: 'authorization_code', code, redirect_uri: `${appUrl}/cb`, client_id: 'int', code_verifier: TEST_VERIFIER,
    });
    expect(issued.status).toBe(200);
    await page.close();
    return ((await issued.json()) as { refresh_token: string }).refresh_token;
  }

  const laptop = await browser.newContext();
  const phone = await browser.newContext();
  const laptopToken = await signIn(laptop);
  const phoneToken = await signIn(phone);

  const page = await laptop.newPage();
  await page.goto(`${authUrl}/logout?client_id=int`);
  expect(await page.textContent('body')).toContain('в этом браузере');
  await page.getByRole('button', { name: 'Выйти' }).click();
  await page.getByRole('heading', { name: 'Вы вышли' }).waitFor({ timeout: 5000 });

  expect(await refresh(laptopToken)).toBe(400);
  expect(await refresh(phoneToken)).toBe(200);
  // Во втором браузере вход жив: тихий вход сразу возвращает в приложение с кодом.
  const phonePage = await phone.newPage();
  await phonePage.goto(authorizeUrl({ prompt: 'none' }));
  await phonePage.waitForURL(`${appUrl}/cb**`, { timeout: 5000 });
  expect(new URL(phonePage.url()).searchParams.get('code')).toBeTruthy();
  // А в первом — нет: тихий вход отвечает login_required.
  const laptopPage = await laptop.newPage();
  await laptopPage.goto(authorizeUrl({ prompt: 'none' }));
  await laptopPage.waitForURL(`${appUrl}/cb**`, { timeout: 5000 });
  expect(new URL(laptopPage.url()).searchParams.get('error')).toBe('login_required');

  await laptop.close();
  await phone.close();
});
