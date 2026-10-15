import { describe, it, expect } from 'vitest';
import { EmailVerificationService } from '../../../src/domain/email-login/email-verification-service.js';
import { EmailSecretService } from '../../../src/domain/email-secret/email-secret.js';
import { InMemoryEmailSecretStore } from '../../../src/adapters/repository/in-memory-email-secret-store.js';
import { InMemoryIdentityRepository } from '../../../src/adapters/repository/in-memory-identity-repository.js';
import { FakeMailer } from '../../../src/adapters/mail/fake-mailer.js';
import { fakeClock } from '../../helpers/fake-clock.js';

const T0 = new Date('2026-07-01T00:00:00Z');

async function make(token = 'tok-abc') {
  const secretStore = new InMemoryEmailSecretStore();
  const secrets = new EmailSecretService(secretStore, fakeClock(T0), () => token, 900);
  const mailer = new FakeMailer();
  const repo = new InMemoryIdentityRepository(fakeClock(T0));
  const service = new EmailVerificationService(secrets, mailer, repo);
  const user = await repo.createUser({ displayName: undefined });
  await repo.addEmail({ userId: user.id, email: 'a@b.com', verified: false });
  return { service, mailer, repo, user };
}

describe('EmailVerificationService', () => {
  it('requestVerification шлёт письмо с токеном на нормализованный email', async () => {
    const { service, mailer } = await make('tok-xyz');
    await service.requestVerification('u', 'A@B.com');
    expect(mailer.last?.to).toBe('a@b.com');
    expect(mailer.last?.text).toContain('tok-xyz');
  });

  it('confirm с верным токеном помечает email подтверждённым', async () => {
    const { service, repo, user } = await make('tok-1');
    await service.requestVerification(user.id, 'a@b.com');
    const ok = await service.confirm(user.id, 'A@B.com', 'tok-1');
    expect(ok).toBe(true);
    const email = await repo.findEmail(user.id, 'a@b.com');
    expect(email?.verified).toBe(true);
  });

  it('confirm с неверным токеном возвращает false и не подтверждает', async () => {
    const { service, repo, user } = await make('tok-1');
    await service.requestVerification(user.id, 'a@b.com');
    expect(await service.confirm(user.id, 'a@b.com', 'wrong')).toBe(false);
    expect((await repo.findEmail(user.id, 'a@b.com'))?.verified).toBe(false);
  });

  it('confirm одноразовый: повторное подтверждение тем же токеном — false', async () => {
    const { service, user } = await make('tok-1');
    await service.requestVerification(user.id, 'a@b.com');
    expect(await service.confirm(user.id, 'a@b.com', 'tok-1')).toBe(true);
    expect(await service.confirm(user.id, 'a@b.com', 'tok-1')).toBe(false);
  });

  it('confirm с верным токеном, но без такого email у пользователя — false', async () => {
    const { service, user } = await make('tok-1');
    await service.requestVerification(user.id, 'unknown@x.com');
    expect(await service.confirm(user.id, 'unknown@x.com', 'tok-1')).toBe(false);
  });
});
