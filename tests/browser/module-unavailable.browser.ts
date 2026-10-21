import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { chromium, type Browser } from 'playwright';
import { temporaryUnavailablePage } from '../../module/server/session-guard.js';

// Страница «сервис входа временно недоступен» из модуля: человек видит текст,
// а браузер сам повторяет запрос и доходит до результата.

let browser: Browser;
let server: http.Server;

beforeAll(async () => {
  browser = await chromium.launch();
});

afterAll(async () => {
  await browser?.close();
  server?.close();
});

it('страница «сервис временно недоступен» сама обновляется и доходит до результата', async () => {
  let hits = 0;
  server = http.createServer((_req, res) => {
    hits += 1;
    if (hits === 1) {
      const out = temporaryUnavailablePage();
      void out.text().then((body) => {
        const headers: Record<string, string> = {};
        out.headers.forEach((value, key) => { headers[key] = value; });
        res.writeHead(out.status, headers);
        res.end(body);
      });
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><meta charset="utf-8"><p>Защищённая страница</p>');
  });
  const appUrl = await new Promise<string>((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)),
  );
  const page = await browser.newPage();
  await page.goto(appUrl);
  await page.getByText('Сервис входа временно недоступен').first().waitFor({ timeout: 5000 });
  await page.getByText('Защищённая страница').waitFor({ timeout: 15_000 });
  expect(hits).toBe(2);
});
