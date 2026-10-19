import { describe, it, expect } from 'vitest';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import type { Config } from '../../../src/config/config.js';
import { issueCsrf, verifyCsrf } from '../../../src/adapters/http/csrf.js';

const config: Config = {
  port: 3016,
  issuerUrl: 'https://auth.example',
  keyAutogenerate: true,
  accessTtlSeconds: 900,
  idTtlSeconds: 900,
  refreshTtlSeconds: 2592000,
  clients: [],
  migrateOnBoot: true,
  ssoTtlSeconds: 2592000,
  ssoCookieName: 'sso',
  csrfCookieName: 'csrf',
  ssoCookieSecure: false,
  trustProxy: 0,
  logLevel: 'silent',
  emailAppName: 'Auth Service',
  rateLimits: {
    identifyPerIp: { limit: 60, windowSeconds: 900 },
    googleNoncePerIp: { limit: 300, windowSeconds: 900 },
    codeRequest: { limit: 3, windowSeconds: 900 },
    codeRequestPerEmail: { limit: 8, windowSeconds: 3600 },
    codeRequestPerIp: { limit: 20, windowSeconds: 3600 },
    codeRequestPerEmailDaily: { limit: 20, windowSeconds: 86400 },
    codeVerifyPerIp: { limit: 30, windowSeconds: 900 },
    token: { limit: 60, windowSeconds: 900 },
    revoke: { limit: 60, windowSeconds: 900 },
  },
};

async function buildTestApp() {
  const app = Fastify({ logger: false });
  await app.register(formbody);
  await app.register(cookie);
  app.get('/issue', async (_req, reply) => {
    const token = issueCsrf(reply, config);
    return { token };
  });
  app.post('/verify', async (req, reply) => {
    const body = req.body as { csrf?: string };
    return reply.send({ ok: verifyCsrf(req, config, body.csrf) });
  });
  await app.ready();
  return app;
}

// Достаём значение конкретной cookie из заголовков set-cookie ответа.
function cookieValue(setCookie: string | string[] | undefined, name: string): string {
  const list = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  const hit = list.find((c) => c.startsWith(`${name}=`));
  if (!hit) throw new Error(`cookie ${name} не выставлена`);
  return decodeURIComponent(hit.split(';')[0]!.split('=')[1]!);
}

describe('CSRF double-submit', () => {
  it('пропускает: токен и полем, и cookie совпадают', async () => {
    const app = await buildTestApp();
    const issued = await app.inject({ method: 'GET', url: '/issue' });
    const token = issued.json<{ token: string }>().token;
    const cookieToken = cookieValue(issued.headers['set-cookie'], config.csrfCookieName);
    expect(cookieToken).toBe(token);

    const res = await app.inject({
      method: 'POST',
      url: '/verify',
      headers: {
        cookie: `${config.csrfCookieName}=${token}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      payload: new URLSearchParams({ csrf: token }).toString(),
    });
    expect(res.json()).toEqual({ ok: true });
    await app.close();
  });

  it('отклоняет: поле не совпадает с cookie', async () => {
    const app = await buildTestApp();
    const issued = await app.inject({ method: 'GET', url: '/issue' });
    const token = issued.json<{ token: string }>().token;

    const res = await app.inject({
      method: 'POST',
      url: '/verify',
      headers: {
        cookie: `${config.csrfCookieName}=${token}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      payload: new URLSearchParams({ csrf: 'подделанное-значение' }).toString(),
    });
    expect(res.json()).toEqual({ ok: false });
    await app.close();
  });

  it('отклоняет: cookie отсутствует', async () => {
    const app = await buildTestApp();
    const res = await app.inject({
      method: 'POST',
      url: '/verify',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ csrf: 'что-угодно' }).toString(),
    });
    expect(res.json()).toEqual({ ok: false });
    await app.close();
  });
});
