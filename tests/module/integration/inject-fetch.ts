import { afterEach, vi } from 'vitest';
import { buildServer } from '../../../src/adapters/http/server.js';
import { makeTestDeps, type TestDeps } from '../../adapters/http/helpers.js';
import type { FastifyInstance } from 'fastify';
import type { Client } from '../../../src/domain/clients/client.js';

// Backend fixtures используют фиксированные часы; модуль должен видеть тот же
// момент при проверке JWT exp. Таймеры fetch/deadline остаются реальными.
afterEach(() => vi.useRealTimers());

// Мост Web fetch -> Fastify app.inject(): модуль думает, что ходит по сети,
// а на деле бьёт в сервис in-process. redirect: 'manual' — 302 сервиса нам
// нужны как данные (Location), а не как автопереход.
export function injectFetch(app: FastifyInstance): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    const url = new URL(req.url);
    const headers: Record<string, string> = {};
    req.headers.forEach((v, k) => {
      headers[k] = v;
    });
    const body = req.method === 'GET' || req.method === 'HEAD' ? undefined : await req.text();
    const res = await app.inject({
      method: req.method as never,
      url: url.pathname + url.search,
      headers,
      payload: body,
    });
    const outHeaders = new Headers();
    for (const [k, v] of Object.entries(res.headers)) {
      if (Array.isArray(v)) for (const item of v) outHeaders.append(k, String(item));
      else if (v !== undefined) outHeaders.append(k, String(v));
    }
    // res.rawPayload — Buffer; в TS 5.9 Uint8Array стал generic по ArrayBufferLike
    // (см. cookie-seal.ts), поэтому явно копируем в Uint8Array<ArrayBuffer> под BodyInit.
    const payload = new Uint8Array(res.rawPayload);
    return new Response(payload, { status: res.statusCode, headers: outHeaders });
  }) as typeof fetch;
}

// Поднимает тестовый сервис с клиентом под адрес приложения модуля и возвращает
// пару (fetch-мост, deps) для регистрации пользователя и т.п.
// type: internal — приложения Гильдии (тихий SSO); external — независимо
// управляемое приложение, которому тихий вход отвечает consent_required.
export async function makeAppFetch(
  appOrigin: string,
  type: Client['type'] = 'internal',
): Promise<{
  fetch: typeof fetch;
  deps: TestDeps;
  app: FastifyInstance;
}> {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date('2026-07-02T00:00:00Z'));
  const client: Client = {
    id: new URL(appOrigin).hostname,
    type,
    redirectUris: [`${appOrigin}/api/auth/callback`],
    allowedProviders: ['email'],
    postLogoutRedirectUris: [`${appOrigin}/`],
  };
  const deps = await makeTestDeps({ clients: [client] });
  const app = buildServer(deps);
  return { fetch: injectFetch(app), deps, app };
}
