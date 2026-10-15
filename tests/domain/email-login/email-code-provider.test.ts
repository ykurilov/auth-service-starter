import { describe, it, expect } from 'vitest';
import { EmailCodeProvider } from '../../../src/domain/email-login/email-code-provider.js';
import { InMemoryLoginChallengeStore } from '../../../src/adapters/repository/in-memory-login-challenge-store.js';
import { FakeMailer } from '../../../src/adapters/mail/fake-mailer.js';
import { InvalidCredentialsError, InvalidEmailError } from '../../../src/domain/email-login/errors.js';
import { advanceableClock } from '../../helpers/advanceable-clock.js';

const T0 = new Date('2026-07-01T00:00:00Z');

function make(codes: string[] = ['123456']) {
  const store = new InMemoryLoginChallengeStore();
  const mailer = new FakeMailer();
  const clock = advanceableClock(T0);
  const queue = [...codes];
  const provider = new EmailCodeProvider(store, mailer, clock, {
    appName: 'Auth Service',
    codeTtlMinutes: 15,
    generateCode: () => queue.shift() ?? codes[codes.length - 1]!,
  });
  return { store, mailer, provider, clock };
}

describe('EmailCodeProvider', () => {
  it('id адаптера — email-code', () => {
    expect(make().provider.id).toBe('email-code');
  });

  it('start отправляет письмо с кодом на нормализованный адрес и даёт случайный handle', async () => {
    const { mailer, provider } = make(['654321']);
    const a = await provider.start({ email: ' User@X.com ', binding: 'b' });
    const b = await provider.start({ email: 'user@x.com', binding: 'b' });
    expect(mailer.last?.to).toBe('user@x.com');
    expect(mailer.sent[0]?.text).toContain('654321');
    expect(a.email).toBe('user@x.com');
    expect(a.handle).not.toBe(b.handle);
    expect(a.handle.length).toBeGreaterThanOrEqual(43);
  });

  it('start с некорректным адресом бросает InvalidEmailError и не пишет письмо', async () => {
    const { mailer, provider } = make();
    await expect(provider.start({ email: 'a@b.com <c@d.com>', binding: 'b' })).rejects.toBeInstanceOf(InvalidEmailError);
    expect(mailer.sent).toHaveLength(0);
  });

  it('verify с верным кодом → ProviderIdentity(emailVerified:true)', async () => {
    const { provider } = make(['111222']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b' });
    expect(await provider.verify({ handle, binding: 'b', code: '111222' })).toEqual({
      provider: 'email',
      subject: 'code:a@b.com',
      email: 'a@b.com',
      emailVerified: true,
      profile: {},
    });
  });

  it('код одноразовый', async () => {
    const { provider } = make(['111222']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b' });
    await provider.verify({ handle, binding: 'b', code: '111222' });
    await expect(provider.verify({ handle, binding: 'b', code: '111222' })).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('неверный код, чужой браузер, просрочка → InvalidCredentialsError', async () => {
    const { provider, clock } = make(['111222']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b' });
    await expect(provider.verify({ handle, binding: 'b', code: '000000' })).rejects.toBeInstanceOf(InvalidCredentialsError);
    await expect(provider.verify({ handle, binding: 'other', code: '111222' })).rejects.toBeInstanceOf(InvalidCredentialsError);
    clock.advance(15 * 60 + 1);
    await expect(provider.verify({ handle, binding: 'b', code: '111222' })).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('лимит 5 проверок на попытку; describe показывает остаток', async () => {
    const { provider } = make(['111222']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b' });
    for (let i = 0; i < 5; i++) {
      await expect(provider.verify({ handle, binding: 'b', code: `x${i}` })).rejects.toBeInstanceOf(InvalidCredentialsError);
    }
    expect(await provider.describe({ handle, binding: 'b' })).toMatchObject({ attemptsLeft: 0 });
    await expect(provider.verify({ handle, binding: 'b', code: '111222' })).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('параллельные попытки одного адреса независимы', async () => {
    const { provider } = make(['111111', '222222']);
    const owner = await provider.start({ email: 'a@b.com', binding: 'owner' });
    const other = await provider.start({ email: 'a@b.com', binding: 'attacker' });
    for (let i = 0; i < 5; i++) await provider.verify({ handle: other.handle, binding: 'attacker', code: `x${i}` }).catch(() => {});
    await expect(provider.verify({ handle: owner.handle, binding: 'owner', code: '111111' })).resolves.toBeTruthy();
  });

  it('resend атомарно заменяет код; лимит переотправок 3', async () => {
    const { provider, mailer } = make(['111111', '222222', '333333', '444444', '555555']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b' });
    expect(await provider.resend({ handle, binding: 'b' })).toEqual({ email: 'a@b.com' });
    expect(mailer.last?.text).toContain('222222');
    await expect(provider.verify({ handle, binding: 'b', code: '111111' })).rejects.toBeInstanceOf(InvalidCredentialsError);
    await provider.resend({ handle, binding: 'b' });
    await provider.resend({ handle, binding: 'b' });
    expect(await provider.resend({ handle, binding: 'b' })).toBeNull();
    await expect(provider.verify({ handle, binding: 'b', code: '444444' })).resolves.toBeTruthy();
  });

  it('отложенная привязка возвращается вместе с личностью почты', async () => {
    const { provider } = make(['111222']);
    const link = { provider: 'google', subject: 'g-1', name: 'G' };
    const { handle } = await provider.start({ email: 'a@corp.example', binding: 'b', link });
    const verified = await provider.verifyChallenge({ handle, binding: 'b', code: '111222' });
    expect(verified.link).toEqual(link);
    expect(verified.identity.email).toBe('a@corp.example');
  });

  it('verify с кривым credential бросает', async () => {
    await expect(make().provider.verify({ email: 'a@b.com' })).rejects.toBeTruthy();
  });
});
