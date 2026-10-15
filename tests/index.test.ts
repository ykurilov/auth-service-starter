import { describe, it, expect } from 'vitest';
import { bootstrap } from '../src/index.js';
import { computeS256Challenge } from '../src/domain/login/pkce.js';

describe('bootstrap', () => {
  it('собирает работающий HTTP-сервер', async () => {
    const { app } = await bootstrap({
      PUBLIC_ISSUER_URL: 'https://auth.example',
      KEY_AUTOGENERATE: 'true',
      LOG_LEVEL: 'silent',
    } as NodeJS.ProcessEnv);
    try {
      const live = await app.inject({ method: 'GET', url: '/live' });
      expect(live.statusCode).toBe(200);
      expect(live.json()).toEqual({ status: 'ok' });

      const discovery = await app.inject({
        method: 'GET',
        url: '/.well-known/openid-configuration',
      });
      expect(discovery.statusCode).toBe(200);
      expect(discovery.json().issuer).toBe('https://auth.example');
    } finally {
      await app.close();
    }
  });

  it('поднимает клиента из CLIENTS_JSON: GET /authorize → форма входа', async () => {
    const client = {
      id: 'shop',
      type: 'external',
      redirectUris: ['https://shop.example/cb'],
      allowedProviders: ['email'],
    };
    const { app } = await bootstrap({
      PUBLIC_ISSUER_URL: 'https://auth.example',
      KEY_AUTOGENERATE: 'true',
      LOG_LEVEL: 'silent',
      CLIENTS_JSON: JSON.stringify([client]),
    } as NodeJS.ProcessEnv);
    try {
      const query = new URLSearchParams({
        client_id: 'shop',
        redirect_uri: 'https://shop.example/cb',
        code_challenge: computeS256Challenge('verifier-достаточно-длинный-1234567890'),
        code_challenge_method: 'S256',
        scope: 'openid',
      }).toString();
      const res = await app.inject({ method: 'GET', url: `/authorize?${query}` });
      expect(res.statusCode).toBe(200);
      expect(res.body).toContain('/authorize/identify');
    } finally {
      await app.close();
    }
  });
});
