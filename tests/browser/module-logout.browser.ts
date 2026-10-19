import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { chromium, type Browser } from 'playwright';
import { createAuthHandlers } from '../../module/server/handlers.js';

// Страница подтверждения выхода ставит CSP form-action. Chrome проверяет его
// и на редиректе после отправки формы, поэтому переход на /logout сервиса
// должен быть разрешён — иначе SSO не завершается.

const servers: http.Server[] = [];
let browser: Browser;

function listen(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)),
  );
}

beforeAll(async () => {
  browser = await chromium.launch();
});

afterAll(async () => {
  await browser?.close();
  for (const server of servers) server.close();
});

it('«Выйти» доводит браузер до /logout сервиса авторизации', async () => {
  const serviceHits: string[] = [];
  const authUrl = await listen((req, res) => {
    serviceHits.push(req.url ?? '');
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Сервис авторизации: выход');
  });
  let handlers: ReturnType<typeof createAuthHandlers> | undefined;
  const appUrl = await listen(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const request = new Request(`${appUrl}${req.url}`, {
      method: req.method,
      headers: req.headers as Record<string, string>,
      body: req.method === 'GET' || req.method === 'HEAD' ? undefined : Buffer.concat(chunks),
    });
    const out = req.method === 'POST' ? await handlers!.POST(request) : await handlers!.GET(request);
    const headers: Record<string, string | string[]> = {};
    out.headers.forEach((value, key) => { if (key !== 'set-cookie') headers[key] = value; });
    headers['set-cookie'] = out.headers.getSetCookie();
    res.writeHead(out.status, headers);
    res.end(Buffer.from(await out.arrayBuffer()));
  });
  handlers = createAuthHandlers({
    env: { AUTH_URL: authUrl, AUTH_APP_URL: appUrl, AUTH_COOKIE_SECRET: 'x'.repeat(40), AUTH_CLIENT_ID: 'browser-test' },
  });

  const page = await browser.newPage();
  const blocked: string[] = [];
  page.on('console', (msg) => { if (/Content Security Policy/i.test(msg.text())) blocked.push(msg.text()); });
  await page.goto(`${appUrl}/api/auth/logout`);
  await page.getByRole('button', { name: 'Выйти' }).click();
  await page.waitForURL(`${authUrl}/logout**`, { timeout: 5000 }).catch(() => undefined);

  expect(blocked).toEqual([]);
  expect(new URL(page.url()).origin).toBe(authUrl);
  expect(serviceHits.some((url) => url.startsWith('/logout?'))).toBe(true);
  expect(await page.textContent('body')).toContain('Сервис авторизации: выход');
});
