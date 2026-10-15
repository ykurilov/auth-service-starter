import { describe, it, expect } from 'vitest';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';

// Exercise the actual CLI against HTTP; JSON content-type on an empty DELETE
// is rejected by Fastify before the admin handler runs.
type Seen = { method?: string; url?: string; type?: string; body: string; authorized: boolean };
const credential = 'cli-test-only-admin-token';

async function withAdminApi(run: (port: number, seen: () => Seen | undefined) => Promise<void>) {
  let request: Seen | undefined;
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      request = { method: req.method, url: req.url, type: req.headers['content-type'], body,
        authorized: req.headers.authorization === 'Bearer ' + credential };
      if (req.method === 'GET') { res.writeHead(200, { 'content-type': 'application/json' }).end('[]'); return; }
      res.writeHead(body === '' && !req.headers['content-type'] ? 204 : 400).end();
    });
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  try { await run((server.address() as { port: number }).port, () => request); }
  finally { await new Promise<void>((done) => server.close(() => done())); }
}

function cli(args: string[], env: Record<string, string>) {
  const base = { ...process.env };
  for (const key of ['ADMIN_API_URL', 'PUBLIC_ISSUER_URL', 'PORT', 'HOST_PORT', 'AUTH_SERVICE_CONTAINER']) delete base[key];
  return promisify(execFile)(process.execPath, [resolve('scripts/client.mjs'), ...args], {
    env: { ...base, ADMIN_API_TOKEN: credential, ...env },
  });
}

// Exercise the actual CLI against HTTP; JSON content-type on an empty DELETE
// is rejected by Fastify before the admin handler runs.
describe('client management CLI HTTP contract', () => {
  it('deletes without a JSON body and keeps the admin credential out of output', async () => {
    await withAdminApi(async (port, seen) => {
      const result = await cli(['delete', 'app.example.com'], { ADMIN_API_URL: 'http://127.0.0.1:' + port });
      expect(seen()).toEqual({ method: 'DELETE', url: '/admin/clients/app.example.com', type: undefined, body: '', authorized: true });
      expect(result.stdout).not.toContain(credential);
      expect(result.stderr).not.toContain(credential);
    });
  });

  // Внутри контейнера CLI ходит в локальный процесс: публичный адрес может
  // ещё не работать (nginx и сертификат настраиваются позже).
  it('by default calls the local process on PORT, not the public issuer', async () => {
    await withAdminApi(async (port, seen) => {
      await cli(['list'], { PORT: String(port), PUBLIC_ISSUER_URL: 'https://auth.invalid' });
      expect(seen()).toMatchObject({ method: 'GET', url: '/admin/clients', authorized: true });
    });
  });

  // На хосте сервис опубликован на HOST_PORT; внутри контейнера тот же .env
  // тоже содержит HOST_PORT, но процесс слушает PORT.
  it('on the host prefers HOST_PORT over PORT', async () => {
    await withAdminApi(async (port, seen) => {
      await cli(['list'], { HOST_PORT: String(port), PORT: '9' });
      expect(seen()).toMatchObject({ method: 'GET', url: '/admin/clients' });
    });
  });

  it('the runtime image marks the container for the CLI', () => {
    const runtime = readFileSync('Dockerfile', 'utf8').split(/^FROM /m).at(-1)!;
    expect(runtime).toMatch(/^ENV AUTH_SERVICE_CONTAINER=1$/m);
  });

  it('inside the container ignores HOST_PORT and uses PORT', async () => {
    await withAdminApi(async (port, seen) => {
      await cli(['list'], { AUTH_SERVICE_CONTAINER: '1', HOST_PORT: '9', PORT: String(port) });
      expect(seen()).toMatchObject({ method: 'GET', url: '/admin/clients' });
    });
  });

  it('ADMIN_API_URL wins over HOST_PORT and PORT', async () => {
    await withAdminApi(async (port, seen) => {
      await cli(['list'], { ADMIN_API_URL: 'http://127.0.0.1:' + port, HOST_PORT: '9', PORT: '9' });
      expect(seen()).toMatchObject({ method: 'GET', url: '/admin/clients' });
    });
  });

  it('refuses a plain HTTP ADMIN_API_URL outside localhost', async () => {
    await expect(cli(['list'], { ADMIN_API_URL: 'http://auth.example.com' })).rejects.toMatchObject({
      stderr: expect.stringContaining('HTTPS'),
    });
  });
});
