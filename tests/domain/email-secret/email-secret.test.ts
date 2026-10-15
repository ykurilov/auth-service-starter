import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  EmailSecretService,
  tokenGenerator,
  numericCodeGenerator,
} from '../../../src/domain/email-secret/email-secret.js';
import { InMemoryEmailSecretStore } from '../../../src/adapters/repository/in-memory-email-secret-store.js';
import { fakeClock } from '../../helpers/fake-clock.js';

const T0 = new Date('2026-07-01T00:00:00Z');

function make(generate: () => string = () => 'FIXED', ttl = 900) {
  const store = new InMemoryEmailSecretStore();
  const service = new EmailSecretService(store, fakeClock(T0), generate, ttl);
  return { store, service };
}

describe('EmailSecretService', () => {
  it('issue возвращает сырой секрет, а хранит только его SHA-256', async () => {
    const { store, service } = make(() => 'PLAINSECRET');
    const secret = await service.issue('email-verify', 'A@B.com');
    expect(secret).toBe('PLAINSECRET');
    const stored = await store.findActive('email-verify', 'a@b.com', T0);
    expect(stored).not.toBeNull();
    expect(stored?.secretHash).toBe(
      createHash('sha256').update('PLAINSECRET').digest('hex'),
    );
    expect(stored?.email).toBe('a@b.com'); // нормализован
  });

  it('verify принимает правильный секрет и гасит его (одноразовость)', async () => {
    const { service } = make(() => 'CODE123');
    await service.issue('email-code-login', 'user@x.com');
    expect(await service.verify('email-code-login', 'user@x.com', 'CODE123')).toBe(true);
    expect(await service.verify('email-code-login', 'user@x.com', 'CODE123')).toBe(false);
  });

  it('verify отклоняет неверный секрет', async () => {
    const { service } = make(() => 'RIGHT');
    await service.issue('email-code-login', 'user@x.com');
    expect(await service.verify('email-code-login', 'user@x.com', 'WRONG')).toBe(false);
  });

  it('verify отклоняет просроченный секрет', async () => {
    const store = new InMemoryEmailSecretStore();
    const issue = new EmailSecretService(store, fakeClock(T0), () => 'S', 900);
    await issue.issue('email-verify', 'u@x.com');
    const later = new EmailSecretService(
      store,
      fakeClock(new Date('2026-07-01T01:00:00Z')),
      () => 'S',
      900,
    );
    expect(await later.verify('email-verify', 'u@x.com', 'S')).toBe(false);
  });

  it('verify нормализует email при поиске', async () => {
    const { service } = make(() => 'S');
    await service.issue('email-verify', 'Mixed@Case.Com');
    expect(await service.verify('email-verify', 'mixed@case.com', 'S')).toBe(true);
  });

  it('numericCodeGenerator даёт код из нужного числа цифр', () => {
    const gen = numericCodeGenerator(6);
    for (let i = 0; i < 50; i++) {
      expect(gen()).toMatch(/^\d{6}$/);
    }
  });

  it('tokenGenerator даёт непустой url-safe токен', () => {
    expect(tokenGenerator()).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('повторный issue инвалидирует прежний код (последний побеждает)', async () => {
    const store = new InMemoryEmailSecretStore();
    let code = 'FIRST';
    const service = new EmailSecretService(store, fakeClock(T0), () => code, 900);
    await service.issue('email-code-login', 'u@x.com');
    code = 'SECOND';
    await service.issue('email-code-login', 'u@x.com');
    expect(await service.verify('email-code-login', 'u@x.com', 'FIRST')).toBe(false);
    expect(await service.verify('email-code-login', 'u@x.com', 'SECOND')).toBe(true);
  });
});
