import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { chromium, type Browser } from 'playwright';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../src/adapters/http/server.js';
import { makeTestDeps } from '../adapters/http/helpers.js';

// Пример Next.js 16 со скелетом по умолчанию (Turbopack, cacheComponents,
// proxy.ts) против настоящего сервиса: закрытая страница уводит на вход,
// после кода из письма открывается кабинет, «Выйти» закрывает сессию
// приложения. Нужны зависимости примера: `npm ci` в examples/nextjs-demo.

const demo = path.resolve(process.env.AUTH_TEST_NEXT_DEMO ?? 'examples/nextjs-demo');
const nextBin = path.join(demo, 'node_modules/.bin/next');

let browser: Browser;
let service: FastifyInstance;
let next: ChildProcess | undefined;
let appUrl: string;
let authUrl: string;

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const server = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = server.address() as net.AddressInfo;
      server.close(() => resolve(port));
    });
  });
}

async function waitForApp(url: string, deadline: number): Promise<void> {
  while (Date.now() < deadline) {
    if (next?.exitCode != null) throw new Error(`next dev завершился с кодом ${next.exitCode}`);
    const ok = await fetch(url, { redirect: 'manual' }).then(() => true, () => false);
    if (ok) return;
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('next dev не ответил за отведённое время');
}

beforeAll(async () => {
  if (!existsSync(nextBin)) return;
  const port = await freePort();
  appUrl = `http://localhost:${port}`;
  const deps = await makeTestDeps({
    clients: [{
      id: 'nextjs-demo', type: 'internal', allowedProviders: ['email'],
      redirectUris: [`${appUrl}/api/auth/callback`], postLogoutRedirectUris: [`${appUrl}/`],
    }],
  });
  service = buildServer(deps);
  authUrl = await service.listen({ port: 0, host: '127.0.0.1' });
  // Формы сверяют Origin с адресом сервиса.
  deps.config.issuerUrl = authUrl;
  // Модуль сверяет срок токенов с настоящим временем, а часы тестового
  // сервиса заморожены на фиксированной дате.
  deps.clock.set(new Date());

  next = spawn(nextBin, ['dev', '--port', String(port), '--hostname', 'localhost'], {
    cwd: demo,
    detached: true,
    stdio: 'ignore',
    env: {
      ...process.env,
      NEXT_TELEMETRY_DISABLED: '1',
      AUTH_URL: authUrl,
      AUTH_APP_URL: appUrl,
      AUTH_CLIENT_ID: 'nextjs-demo',
      AUTH_COOKIE_SECRET: 'next-demo-browser-test-secret-0123456789',
    },
  });
  await waitForApp(`${appUrl}/api/auth/me`, Date.now() + 90_000);
  browser = await chromium.launch();
}, 120_000);

afterAll(async () => {
  await browser?.close();
  // Отрицательный pid — вся группа процессов next dev, включая его воркеры.
  if (next?.pid && next.exitCode == null) process.kill(-next.pid, 'SIGTERM');
  await service?.close();
});

it.skipIf(!existsSync(nextBin))('Next.js 16: вход, кабинет и выход в настоящем Chromium', async () => {
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto(`${appUrl}/dashboard`);
  await page.waitForURL(`${authUrl}/**`, { timeout: 60_000 });
  await page.getByLabel(/почт/i).fill('student@example.test');
  await page.getByRole('button', { name: 'Получить код' }).click();
  await page.getByLabel(/код/i).fill('CODE55');
  await page.getByRole('button', { name: /Войти/ }).click();

  await page.waitForURL(`${appUrl}/dashboard`, { timeout: 60_000 });
  await page.getByRole('heading', { name: 'Личный кабинет' }).waitFor();
  await expect.poll(() => page.textContent('pre')).toContain('student@example.test');

  await page.goto(`${appUrl}/`);
  await page.getByText('Вы вошли как').waitFor({ timeout: 30_000 });

  await page.getByRole('link', { name: 'Выйти' }).click();
  await page.getByRole('button', { name: 'Выйти' }).click();
  await page.waitForURL(`${authUrl}/logout**`, { timeout: 10_000 });

  const me = await context.request.get(`${appUrl}/api/auth/me`);
  expect(me.status()).toBe(401);
  await context.close();
}, 180_000);
