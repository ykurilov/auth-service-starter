import { describe, it, expect } from 'vitest';
import { OidcClient } from '../../../module/server/core/oidc-client.js';
import { loadModuleConfig } from '../../../module/server/core/config.js';

const env = {
  AUTH_URL: 'https://auth.test',
  AUTH_APP_URL: 'https://app.test',
  AUTH_COOKIE_SECRET: 'секрет-достаточной-длины-32-символа-минимум-1',
};

function clientWith(handler: (req: Request) => Promise<Response> | Response) {
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    return handler(req);
  }) as typeof fetch;
  return new OidcClient(loadModuleConfig({ env, fetch: fetchImpl }));
}

describe('OidcClient.buildAuthorizeUrl', () => {
  it('собирает /authorize со всеми PKCE-параметрами', () => {
    const client = clientWith(() => new Response(''));
    const url = new URL(
      client.buildAuthorizeUrl({ challenge: 'chal', state: 'st1' }),
    );
    expect(url.origin + url.pathname).toBe('https://auth.test/authorize');
    expect(url.searchParams.get('client_id')).toBe('app.test');
    expect(url.searchParams.get('redirect_uri')).toBe('https://app.test/api/auth/callback');
    expect(url.searchParams.get('code_challenge')).toBe('chal');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('scope')).toBe('openid profile email');
    expect(url.searchParams.get('state')).toBe('st1');
  });
});

describe('OidcClient.buildAuthorizeUrl: prompt', () => {
  it('без prompt параметр не добавляется', () => {
    const url = new URL(clientWith(() => new Response('')).buildAuthorizeUrl({ challenge: 'c', state: 's' }));
    expect(url.searchParams.has('prompt')).toBe(false);
  });
  it('prompt=none для тихой проверки', () => {
    const url = new URL(
      clientWith(() => new Response('')).buildAuthorizeUrl({ challenge: 'c', state: 's', prompt: 'none' }),
    );
    expect(url.searchParams.get('prompt')).toBe('none');
  });
});

describe('OidcClient.exchangeCode', () => {
  it('POST /oauth/token JSON grant_type=authorization_code -> токены', async () => {
    let seen: { url: string; body: any; contentType: string | null } | null = null;
    const client = clientWith(async (req) => {
      seen = {
        url: req.url,
        body: await req.json(),
        contentType: req.headers.get('content-type'),
      };
      return Response.json({
        access_token: 'a',
        id_token: 'i',
        refresh_token: 'r',
        token_type: 'Bearer',
        expires_in: 900,
      });
    });
    const tokens = await client.exchangeCode({ code: 'c', verifier: 'v' });
    expect(tokens).toEqual({ accessToken: 'a', idToken: 'i', refreshToken: 'r', expiresIn: 900 });
    expect(seen!.url).toBe('https://auth.test/oauth/token');
    expect(seen!.contentType).toContain('application/json');
    expect(seen!.body).toEqual({
      grant_type: 'authorization_code',
      code: 'c',
      redirect_uri: 'https://app.test/api/auth/callback',
      client_id: 'app.test',
      code_verifier: 'v',
    });
  });

  it('ошибка 400 invalid_grant -> OidcError с error', async () => {
    const client = clientWith(async () =>
      Response.json({ error: 'invalid_grant' }, { status: 400 }),
    );
    await expect(client.exchangeCode({ code: 'c', verifier: 'v' })).rejects.toMatchObject({
      error: 'invalid_grant',
    });
  });

  it('сбой fetch (сеть) -> OidcError с error=network_error', async () => {
    const client = clientWith(async () => {
      throw new TypeError('fetch failed');
    });
    await expect(client.exchangeCode({ code: 'c', verifier: 'v' })).rejects.toMatchObject({
      name: 'OidcError',
      error: 'network_error',
    });
  });

  it('200 с не-JSON телом -> OidcError с error=invalid_response', async () => {
    const client = clientWith(async () => new Response('не json', { status: 200 }));
    await expect(client.exchangeCode({ code: 'c', verifier: 'v' })).rejects.toMatchObject({
      name: 'OidcError',
      error: 'invalid_response',
    });
  });
});

describe('OidcClient.refreshTokens', () => {
  it('POST grant_type=refresh_token -> новые токены', async () => {
    let body: any = null;
    const client = clientWith(async (req) => {
      body = await req.json();
      return Response.json({
        access_token: 'a2',
        id_token: 'i2',
        refresh_token: 'r2',
        token_type: 'Bearer',
        expires_in: 900,
      });
    });
    const tokens = await client.refreshTokens('r1');
    expect(body).toEqual({ grant_type: 'refresh_token', refresh_token: 'r1' });
    expect(tokens.refreshToken).toBe('r2');
  });

  it('отзыв/истечение -> 400 invalid_grant -> OidcError', async () => {
    const client = clientWith(async () =>
      Response.json({ error: 'invalid_grant' }, { status: 400 }),
    );
    await expect(client.refreshTokens('r1')).rejects.toMatchObject({ error: 'invalid_grant' });
  });
});

describe('OidcClient.revoke', () => {
  it('POST /oauth/revoke JSON { token }; ошибки не бросает', async () => {
    let body: any = null;
    const client = clientWith(async (req) => {
      body = await req.json();
      return new Response(null, { status: 200 });
    });
    await client.revoke('r1');
    expect(body).toEqual({ token: 'r1' });
  });

  it('сетевой сбой revoke проглатывается (logout всё равно локально чистит)', async () => {
    const client = clientWith(async () => {
      throw new Error('network');
    });
    await expect(client.revoke('r1')).resolves.toBeUndefined();
  });

  it('buildLogoutUrl -> /logout с client_id и post_logout_redirect_uri', () => {
    const client = clientWith(() => new Response(''));
    const url = new URL(client.buildLogoutUrl());
    expect(url.origin + url.pathname).toBe('https://auth.test/logout');
    expect(url.searchParams.get('client_id')).toBe('app.test');
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe('https://app.test/');
  });
});
