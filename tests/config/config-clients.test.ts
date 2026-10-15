import { describe, it, expect } from 'vitest';
import { loadConfig } from '../../src/config/config.js';

const BASE = { PUBLIC_ISSUER_URL: 'https://auth.example.com' };

describe('loadConfig — клиенты и SSO-cookie', () => {
  it('без CLIENTS_JSON: clients пуст', () => {
    const cfg = loadConfig({ ...BASE } as NodeJS.ProcessEnv);
    expect(cfg.clients).toEqual([]);
  });

  it('валидный CLIENTS_JSON парсится в реестр клиентов', () => {
    const cfg = loadConfig({
      ...BASE,
      CLIENTS_JSON:
        '[{"id":"app","type":"external","redirectUris":["https://a/cb"],"allowedProviders":["email"]}]',
    } as NodeJS.ProcessEnv);
    expect(cfg.clients.length).toBe(1);
    expect(cfg.clients[0]!.id).toBe('app');
    expect(cfg.clients[0]!.type).toBe('external');
  });

  it('битый CLIENTS_JSON: loadConfig бросает', () => {
    expect(() =>
      loadConfig({ ...BASE, CLIENTS_JSON: '{не json' } as NodeJS.ProcessEnv),
    ).toThrow();
  });

  it('CLIENTS_JSON с http redirect_uri (не localhost) отклоняется — как и Admin API', () => {
    expect(() =>
      loadConfig({
        ...BASE,
        CLIENTS_JSON:
          '[{"id":"app","type":"external","redirectUris":["http://evil/cb"],"allowedProviders":["email"]}]',
      } as NodeJS.ProcessEnv),
    ).toThrow();
  });

  it('CLIENTS_JSON с неизвестным провайдером отклоняется', () => {
    expect(() =>
      loadConfig({
        ...BASE,
        CLIENTS_JSON:
          '[{"id":"app","type":"external","redirectUris":["https://a/cb"],"allowedProviders":["telepathy"]}]',
      } as NodeJS.ProcessEnv),
    ).toThrow();
  });

  it('CLIENTS_JSON: google запрещён внешнему клиенту (как в Admin API)', () => {
    expect(() =>
      loadConfig({
        ...BASE,
        CLIENTS_JSON:
          '[{"id":"app","type":"external","redirectUris":["https://a/cb"],"allowedProviders":["google"]}]',
      } as NodeJS.ProcessEnv),
    ).toThrow();
  });

  it('CLIENTS_JSON: localhost по http разрешён (совпадает с доменным правилом)', () => {
    const cfg = loadConfig({
      ...BASE,
      CLIENTS_JSON:
        '[{"id":"local","type":"internal","redirectUris":["http://localhost:3005/cb"],"allowedProviders":["email","google"]}]',
    } as NodeJS.ProcessEnv);
    expect(cfg.clients[0]!.redirectUris[0]).toBe('http://localhost:3005/cb');
  });

  it('ssoTtlSeconds по умолчанию 30 дней', () => {
    const cfg = loadConfig({ ...BASE } as NodeJS.ProcessEnv);
    expect(cfg.ssoTtlSeconds).toBe(2592000);
  });

  it('дефолтные имена cookie', () => {
    const cfg = loadConfig({ ...BASE } as NodeJS.ProcessEnv);
    expect(cfg.ssoCookieName).toBe('sso');
    expect(cfg.csrfCookieName).toBe('csrf');
  });

  it('ssoCookieSecure: дефолт true, "false" -> false', () => {
    expect(loadConfig({ ...BASE } as NodeJS.ProcessEnv).ssoCookieSecure).toBe(true);
    expect(
      loadConfig({ ...BASE, SSO_COOKIE_SECURE: 'false' } as NodeJS.ProcessEnv)
        .ssoCookieSecure,
    ).toBe(false);
  });
});
