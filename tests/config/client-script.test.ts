import { describe, it, expect } from 'vitest';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';
import { createServer } from 'node:http';

// Exercise the actual CLI against HTTP; JSON content-type on an empty DELETE
// is rejected by Fastify before the admin handler runs.
describe('client management CLI HTTP contract', () => {
  it('deletes without a JSON body and keeps the admin credential out of output', async () => {
    let request: { method?: string; type?: string; body: string; authorized: boolean } | undefined;
    const credential = 'cli-test-only-admin-token';
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        request = { method: req.method, type: req.headers['content-type'], body,
          authorized: req.headers.authorization === 'Bearer ' + credential };
        res.writeHead(body === '' && !req.headers['content-type'] ? 204 : 400).end();
      });
    });
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
    try {
      const address = server.address() as { port: number };
      const result = await promisify(execFile)(process.execPath, [resolve('scripts/client.mjs'), 'delete', 'app.example.com'], {
        env: { ...process.env, PUBLIC_ISSUER_URL: 'http://127.0.0.1:' + address.port, ADMIN_API_TOKEN: credential },
      });
      expect(request).toEqual({ method: 'DELETE', type: undefined, body: '', authorized: true });
      expect(result.stdout).not.toContain(credential);
      expect(result.stderr).not.toContain(credential);
    } finally { await new Promise<void>((done) => server.close(() => done())); }
  });
});
