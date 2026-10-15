import { describe, it, expect } from 'vitest';
import { loadModuleConfig } from '../../../module/server/core/config.js';

const base = {
  AUTH_URL: 'https://auth.example.com',
  AUTH_APP_URL: 'https://app.example.com',
  AUTH_COOKIE_SECRET: 'секрет-достаточной-длины-32-символа-минимум-1',
};

describe('loadModuleConfig', () => {
  it('client_id по умолчанию = hostname(AUTH_APP_URL)', () => {
    const cfg = loadModuleConfig({ env: base });
    expect(cfg.clientId).toBe('app.example.com');
    expect(cfg.authUrl).toBe('https://auth.example.com');
    expect(cfg.appUrl).toBe('https://app.example.com');
  });

  it('AUTH_CLIENT_ID переопределяет client_id', () => {
    const cfg = loadModuleConfig({ env: { ...base, AUTH_CLIENT_ID: 'custom-id' } });
    expect(cfg.clientId).toBe('custom-id');
  });

  it('нормализует AUTH_URL/AUTH_APP_URL до origin (без хвостового пути и слэша)', () => {
    const cfg = loadModuleConfig({
      env: { ...base, AUTH_URL: 'https://auth.example.com/', AUTH_APP_URL: 'https://app.example.com/x' },
    });
    expect(cfg.authUrl).toBe('https://auth.example.com');
    expect(cfg.appUrl).toBe('https://app.example.com');
  });

  it.each(['http://auth.example.com', 'ftp://auth.example.com', 'https://user:pass@auth.example.com', 'https://auth.example.com/?secret=x', 'https://auth.example.com/#x'])('rejects insecure or credential-bearing URL %s', (value) => {
    expect(() => loadModuleConfig({ env: { ...base, AUTH_URL: value } })).toThrow(/AUTH_URL/);
    expect(() => loadModuleConfig({ env: { ...base, AUTH_APP_URL: value } })).toThrow(/AUTH_APP_URL/);
  });

  it.each(['http://localhost:3000', 'http://127.0.0.1:3000', 'http://[::1]:3000'])('allows local HTTP %s', (value) => {
    expect(loadModuleConfig({ env: { ...base, AUTH_URL: value, AUTH_APP_URL: value } }).appUrl).toBe(value);
  });

  it('отсутствие AUTH_URL -> русская ошибка', () => {
    const { AUTH_URL, ...rest } = base;
    expect(() => loadModuleConfig({ env: rest })).toThrowError(/AUTH_URL/);
  });

  it('короткий AUTH_COOKIE_SECRET (<32) -> русская ошибка про длину', () => {
    expect(() =>
      loadModuleConfig({ env: { ...base, AUTH_COOKIE_SECRET: 'коротко' } }),
    ).toThrowError(/32/);
  });

  it('невалидный AUTH_APP_URL -> русская ошибка', () => {
    expect(() =>
      loadModuleConfig({ env: { ...base, AUTH_APP_URL: 'не-url' } }),
    ).toThrowError(/AUTH_APP_URL/);
  });

  it('без options.env берёт переменные из process.env (getUser без параметров)', () => {
    const saved = { ...process.env };
    Object.assign(process.env, base);
    try {
      const cfg = loadModuleConfig();
      expect(cfg.clientId).toBe('app.example.com');
    } finally {
      delete process.env.AUTH_URL;
      delete process.env.AUTH_APP_URL;
      delete process.env.AUTH_COOKIE_SECRET;
      Object.assign(process.env, saved);
    }
  });

  it('прокидывает внедрённый fetch', () => {
    const fake = (async () => new Response('')) as typeof fetch;
    const cfg = loadModuleConfig({ env: base, fetch: fake });
    expect(cfg.fetch).toBe(fake);
  });
});
