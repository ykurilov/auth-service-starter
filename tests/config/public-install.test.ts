import { describe, it, expect } from 'vitest';
import { loadConfig } from '../../src/config/config.js';
import { bootstrap } from '../../src/index.js';

describe('portable installation config', () => {
  it('поддерживает явные адреса proxy, а token-бюджет рассчитан на серверные приложения', () => {
    const config = loadConfig({ PUBLIC_ISSUER_URL: 'https://auth.example.com', TRUST_PROXY: 'loopback,172.30.240.1,10.2.0.0/24' });
    expect(config.trustProxy).toEqual(['loopback', '172.30.240.1', '10.2.0.0/24']);
    expect(config.rateLimits.token.limit).toBe(10000);
    expect(loadConfig({ PUBLIC_ISSUER_URL: 'https://auth.example.com', TOKEN_RATE_LIMIT: '20000' }).rateLimits.token.limit).toBe(20000);
  });
  it('не принимает небезопасный issuer и некорректные сроки', () => {
    for (const issuer of ['http://auth.example.com', 'https://auth.example.com/path', 'https://user:password@auth.example.com', 'ftp://auth.example.com']) {
      expect(() => loadConfig({ PUBLIC_ISSUER_URL: issuer })).toThrow();
    }
    expect(loadConfig({ PUBLIC_ISSUER_URL: 'http://localhost:3016' }).issuerUrl).toBe('http://localhost:3016');
    expect(() => loadConfig({ PUBLIC_ISSUER_URL: 'https://auth.example.com', ACCESS_TTL_SECONDS: '-1' })).toThrow();
    expect(() => loadConfig({ PUBLIC_ISSUER_URL: 'https://auth.example.com', TRUST_PROXY: '10.0.0.1/99' })).toThrow();
  });
  it('production отказывает до открытия БД, если почта не настроена', async () => {
    await expect(bootstrap({ NODE_ENV: 'production', PUBLIC_ISSUER_URL: 'https://auth.example.com' })).rejects.toThrow('RESEND_API_KEY');
  });
  it('production не запускается на временной памяти', async () => {
    await expect(bootstrap({ NODE_ENV: 'production', PUBLIC_ISSUER_URL: 'https://auth.example.com', RESEND_API_KEY: 'test-only', EMAIL_FROM: 'auth@example.com' })).rejects.toThrow('DATABASE_URL');
  });
});
