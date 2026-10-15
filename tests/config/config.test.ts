import { describe, it, expect } from 'vitest';
import { loadConfig } from '../../src/config/config.js';

describe('loadConfig', () => {
  it('парсит валидное окружение с дефолтами', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
    } as NodeJS.ProcessEnv);

    expect(cfg.issuerUrl).toBe('https://auth.example.com');
    expect(cfg.accessTtlSeconds).toBe(900);
    expect(cfg.keyAutogenerate).toBe(false);
  });

  it('нормализует литеральные \\n в PEM-ключе', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
      RSA_PRIVATE_KEY: '-----BEGIN-----\\nBODY\\n-----END-----',
    } as NodeJS.ProcessEnv);

    expect(cfg.rsaPrivateKey).toBe('-----BEGIN-----\nBODY\n-----END-----');
  });

  it('бросает ошибку без обязательного PUBLIC_ISSUER_URL', () => {
    expect(() => loadConfig({} as NodeJS.ProcessEnv)).toThrow();
  });

  it('refreshTtlSeconds по умолчанию 30 дней', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
    } as NodeJS.ProcessEnv);
    expect(cfg.refreshTtlSeconds).toBe(2592000);
  });

  it('refreshTtlSeconds читается из env', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
      REFRESH_TTL_SECONDS: '600',
    } as NodeJS.ProcessEnv);
    expect(cfg.refreshTtlSeconds).toBe(600);
  });

  it('databaseUrl не задан по умолчанию', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
    } as NodeJS.ProcessEnv);
    expect(cfg.databaseUrl).toBeUndefined();
  });

  it('databaseUrl читается из DATABASE_URL', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
      DATABASE_URL: 'postgres://user:pw@localhost:5432/auth',
    } as NodeJS.ProcessEnv);
    expect(cfg.databaseUrl).toBe('postgres://user:pw@localhost:5432/auth');
  });

  it('redisUrl читается из REDIS_URL', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
      REDIS_URL: 'redis://localhost:6379',
    } as NodeJS.ProcessEnv);
    expect(cfg.redisUrl).toBe('redis://localhost:6379');
  });

  it('лимиты кодов по умолчанию: бюджеты по IP и по адресу (час и сутки)', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
    } as NodeJS.ProcessEnv);
    expect(cfg.rateLimits.codeVerifyPerIp).toEqual({ limit: 30, windowSeconds: 900 });
    expect(cfg.rateLimits.codeRequestPerIp).toEqual({ limit: 20, windowSeconds: 3600 });
    expect(cfg.rateLimits.codeRequestPerEmail).toEqual({ limit: 5, windowSeconds: 3600 });
    expect(cfg.rateLimits.codeRequestPerEmailDaily).toEqual({ limit: 20, windowSeconds: 86400 });
  });

  it('migrateOnBoot по умолчанию true', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
    } as NodeJS.ProcessEnv);
    expect(cfg.migrateOnBoot).toBe(true);
  });

  it('migrateOnBoot=false отключается через env', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
      MIGRATE_ON_BOOT: 'false',
    } as NodeJS.ProcessEnv);
    expect(cfg.migrateOnBoot).toBe(false);
  });

  it('trustProxy по умолчанию 0 (не доверяем прокси)', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
    } as NodeJS.ProcessEnv);
    expect(cfg.trustProxy).toBe(0);
  });

  it('trustProxy=false трактуется как 0', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
      TRUST_PROXY: 'false',
    } as NodeJS.ProcessEnv);
    expect(cfg.trustProxy).toBe(0);
  });

  it('trustProxy=true трактуется как один хоп (безопасно, без spoofing XFF)', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
      TRUST_PROXY: 'true',
    } as NodeJS.ProcessEnv);
    expect(cfg.trustProxy).toBe(1);
  });

  it('trustProxy принимает число хопов', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
      TRUST_PROXY: '2',
    } as NodeJS.ProcessEnv);
    expect(cfg.trustProxy).toBe(2);
  });

  it('trustProxy с мусором — ошибка конфигурации', () => {
    expect(() =>
      loadConfig({
        PUBLIC_ISSUER_URL: 'https://auth.example.com',
        TRUST_PROXY: 'yes-please',
      } as NodeJS.ProcessEnv),
    ).toThrow();
  });

  it('resendApiKey/emailFrom не заданы по умолчанию', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
    } as NodeJS.ProcessEnv);
    expect(cfg.resendApiKey).toBeUndefined();
    expect(cfg.emailFrom).toBeUndefined();
    expect(cfg.emailFromName).toBeUndefined();
  });

  it('resendApiKey/emailFrom/emailFromName читаются из env (с trim)', () => {
    const cfg = loadConfig({
      PUBLIC_ISSUER_URL: 'https://auth.example.com',
      RESEND_API_KEY: '  re_test_123  ',
      EMAIL_FROM: 'noreply@example.com',
      EMAIL_FROM_NAME: 'Auth Service',
    } as NodeJS.ProcessEnv);
    expect(cfg.resendApiKey).toBe('re_test_123');
    expect(cfg.emailFrom).toBe('noreply@example.com');
    expect(cfg.emailFromName).toBe('Auth Service');
  });
});
