import { describe, it, expect } from 'vitest';
import { IdentityService } from '../../src/domain/identity/identity-service.js';
import { InMemoryIdentityRepository } from '../../src/adapters/repository/in-memory-identity-repository.js';
import { EmailCodeProvider } from '../../src/domain/email-login/email-code-provider.js';
import { InMemoryLoginChallengeStore } from '../../src/adapters/repository/in-memory-login-challenge-store.js';
import { FakeMailer } from '../../src/adapters/mail/fake-mailer.js';
import { fakeClock } from '../helpers/fake-clock.js';

const T0 = new Date('2026-07-01T00:00:00Z');

function makeCodeProvider(clock: ReturnType<typeof fakeClock>): EmailCodeProvider {
  return new EmailCodeProvider(new InMemoryLoginChallengeStore(), new FakeMailer(), clock, {
    appName: 'Auth Service',
    codeTtlMinutes: 15,
    generateCode: () => 'CODE55',
  });
}

// Вход по коду в рамках одной попытки (браузер 'b').
async function codeLogin(provider: EmailCodeProvider, email: string) {
  const { handle } = await provider.start({ email, binding: 'b' });
  return provider.verify({ handle, binding: 'b', code: 'CODE55' });
}

describe('интеграция входа по email (код)', () => {
  it('вход по коду создаёт пользователя с подтверждённой почтой; повтор тем же email → тот же пользователь', async () => {
    const clock = fakeClock(T0);
    const repo = new InMemoryIdentityRepository(clock);
    const identity = new IdentityService(repo);
    const codeProvider = makeCodeProvider(clock);

    // 1. Первый вход по коду -> новый пользователь. Код доказывает владение
    //    почтой, поэтому email сразу подтверждён (verified=true) — без
    //    отдельного шага подтверждения.
    const pidFirst = await codeLogin(codeProvider, 'User@X.com');
    const first = await identity.resolveLogin(pidFirst);
    expect(first.createdUser).toBe(true);
    expect((await repo.findEmail(first.user.id, 'user@x.com'))?.verified).toBe(true);

    // 2. Повторный вход тем же email (иной регистр) -> тот же пользователь.
    //    Слияние через ПОДТВЕРЖДЁННЫЙ email — единственный слот личности для
    //    входа по почте, поэтому раздельных аккаунтов не возникает.
    const pidSecond = await codeLogin(codeProvider, 'user@x.com');
    const second = await identity.resolveLogin(pidSecond);
    expect(second.createdUser).toBe(false);
    expect(second.user.id).toBe(first.user.id);
  });

  it('разные email не сливаются в одного пользователя', async () => {
    const clock = fakeClock(T0);
    const repo = new InMemoryIdentityRepository(clock);
    const identity = new IdentityService(repo);
    const codeProvider = makeCodeProvider(clock);

    const a = await identity.resolveLogin(await codeLogin(codeProvider, 'a@x.com'));
    const b = await identity.resolveLogin(await codeLogin(codeProvider, 'b@x.com'));

    expect(a.user.id).not.toBe(b.user.id);
  });
});
