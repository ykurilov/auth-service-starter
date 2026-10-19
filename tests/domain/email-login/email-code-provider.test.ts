import { describe, it, expect } from 'vitest';
import { EmailCodeProvider } from '../../../src/domain/email-login/email-code-provider.js';
import { InMemoryLoginChallengeStore } from '../../../src/adapters/repository/in-memory-login-challenge-store.js';
import { FakeMailer } from '../../../src/adapters/mail/fake-mailer.js';
import {
  ChallengeClientChangedError,
  InvalidCredentialsError,
  InvalidEmailError,
} from '../../../src/domain/email-login/errors.js';
import { MailDeliveryError } from '../../../src/ports/mailer.js';
import { advanceableClock } from '../../helpers/advanceable-clock.js';

// Клиент, под которым начинается и проверяется попытка входа.
const TEST_CLIENT = { id: 'app', registrationId: '00000000-0000-4000-8000-000000000001' };

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
    const a = await provider.start({ email: ' User@X.com ', binding: 'b', client: TEST_CLIENT });
    const b = await provider.start({ email: 'user@x.com', binding: 'b', client: TEST_CLIENT });
    expect(mailer.last?.to).toBe('user@x.com');
    expect(mailer.sent[0]?.text).toContain('654321');
    expect(a.email).toBe('user@x.com');
    expect(a.handle).not.toBe(b.handle);
    expect(a.handle.length).toBeGreaterThanOrEqual(43);
  });

  it('start с некорректным адресом бросает InvalidEmailError и не пишет письмо', async () => {
    const { mailer, provider } = make();
    await expect(provider.start({ email: 'a@b.com <c@d.com>', binding: 'b', client: TEST_CLIENT })).rejects.toBeInstanceOf(InvalidEmailError);
    expect(mailer.sent).toHaveLength(0);
  });

  it('verify с верным кодом → ProviderIdentity(emailVerified:true)', async () => {
    const { provider } = make(['111222']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    expect(await provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '111222' })).toEqual({
      provider: 'email',
      subject: 'code:a@b.com',
      email: 'a@b.com',
      emailVerified: true,
      profile: {},
    });
  });

  it('код одноразовый', async () => {
    const { provider } = make(['111222']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    await provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '111222' });
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '111222' })).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('неверный код, чужой браузер, просрочка → InvalidCredentialsError', async () => {
    const { provider, clock } = make(['111222']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '000000' })).rejects.toBeInstanceOf(InvalidCredentialsError);
    await expect(provider.verify({ handle, binding: 'other', client: TEST_CLIENT, code: '111222' })).rejects.toBeInstanceOf(InvalidCredentialsError);
    clock.advance(15 * 60 + 1);
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '111222' })).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('лимит 5 проверок на попытку; describe показывает остаток', async () => {
    const { provider } = make(['111222']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    for (let i = 0; i < 5; i++) {
      await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: `x${i}` })).rejects.toBeInstanceOf(InvalidCredentialsError);
    }
    expect(await provider.describe({ handle, binding: 'b' })).toMatchObject({ attemptsLeft: 0 });
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '111222' })).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('параллельные попытки одного адреса независимы', async () => {
    const { provider } = make(['111111', '222222']);
    const owner = await provider.start({ email: 'a@b.com', binding: 'owner', client: TEST_CLIENT });
    const other = await provider.start({ email: 'a@b.com', binding: 'attacker', client: TEST_CLIENT });
    for (let i = 0; i < 5; i++) await provider.verify({ handle: other.handle, binding: 'attacker', client: TEST_CLIENT, code: `x${i}` }).catch(() => {});
    await expect(provider.verify({ handle: owner.handle, binding: 'owner', client: TEST_CLIENT, code: '111111' })).resolves.toBeTruthy();
  });

  it('resend атомарно заменяет код; лимит переотправок 3', async () => {
    const { provider, mailer } = make(['111111', '222222', '333333', '444444', '555555']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    expect(await provider.resend({ handle, binding: 'b', client: TEST_CLIENT })).toEqual({ email: 'a@b.com' });
    expect(mailer.last?.text).toContain('222222');
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '111111' })).rejects.toBeInstanceOf(InvalidCredentialsError);
    await provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    await provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    expect(await provider.resend({ handle, binding: 'b', client: TEST_CLIENT })).toBeNull();
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '444444' })).resolves.toBeTruthy();
  });

  it('T08: сбой отправки при переотправке — прежний код действует, переотправка не списана', async () => {
    const { provider, mailer } = make(['111111', '222222', '333333']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    const send = mailer.send.bind(mailer);
    mailer.send = async () => { throw new MailDeliveryError('timeout'); };
    await expect(provider.resend({ handle, binding: 'b', client: TEST_CLIENT })).rejects.toBeInstanceOf(MailDeliveryError);
    mailer.send = send;
    expect(await provider.describe({ handle, binding: 'b' })).toMatchObject({ resendsLeft: 3 });
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '111111' })).resolves.toBeTruthy();
  });

  it('T08, P2-1: слот повтора занят до письма, а код меняется только после отправки', async () => {
    const { provider, mailer, store } = make(['111111', '222222']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    const records = (store as unknown as { records: { codeHash: string; resends: number }[] }).records;
    const initialHash = records[0]!.codeHash;
    const send = mailer.send.bind(mailer);
    let duringSend: { codeHash: string; resends: number } | null = null;
    mailer.send = async (email) => {
      duringSend = { ...records[0]! };
      await send(email);
    };
    await provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    expect(duringSend).toEqual(expect.objectContaining({ codeHash: initialHash, resends: 1 }));
    expect(records[0]!.codeHash).not.toBe(initialHash);
  });

  it('T21: письмо первого шага не подтвердилось — попытка остаётся, ошибка несёт её handle', async () => {
    const { provider, mailer } = make(['111111']);
    mailer.send = async () => { throw new MailDeliveryError('timeout'); };
    const err = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MailDeliveryError);
    const handle = (err as { challenge: { handle: string } }).challenge.handle;
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '111111' })).resolves.toBeTruthy();
  });

  it('T02: попытка другой регистрации клиента не проверяется, не гасится и не переотправляется', async () => {
    const { provider, mailer } = make(['111111', '222222']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    const recreated = { id: 'app', registrationId: '00000000-0000-4000-8000-000000000002' };
    await expect(provider.verify({ handle, binding: 'b', code: '111111', client: recreated }))
      .rejects.toBeInstanceOf(ChallengeClientChangedError);
    await expect(provider.verify({ handle, binding: 'b', code: '111111', client: { id: 'other' } }))
      .rejects.toBeInstanceOf(ChallengeClientChangedError);
    const sent = mailer.sent.length;
    await expect(provider.resend({ handle, binding: 'b', client: recreated }))
      .rejects.toBeInstanceOf(ChallengeClientChangedError);
    expect(mailer.sent.length).toBe(sent);
    const view = await provider.describe({ handle, binding: 'b' });
    expect(view?.startedFor(recreated)).toBe(false);
    expect(view?.startedFor(TEST_CLIENT)).toBe(true);
    await expect(provider.verify({ handle, binding: 'b', code: '111111', client: TEST_CLIENT })).resolves.toBeTruthy();
  });

  it('отложенная привязка возвращается вместе с личностью почты', async () => {
    const { provider } = make(['111222']);
    const link = { provider: 'google', subject: 'g-1', name: 'G' };
    const { handle } = await provider.start({ email: 'a@corp.example', binding: 'b', client: TEST_CLIENT, link });
    const verified = await provider.verifyChallenge({ handle, binding: 'b', client: TEST_CLIENT, code: '111222' });
    expect(verified.link).toEqual(link);
    expect(verified.identity.email).toBe('a@corp.example');
  });

  it('verify с кривым credential бросает', async () => {
    await expect(make().provider.verify({ email: 'a@b.com' })).rejects.toBeTruthy();
  });

  it('R20: попытка привязки Google — письмо о привязке, и при повторной отправке тоже', async () => {
    const { mailer, provider } = make(['111111', '222222']);
    const { handle } = await provider.start({
      email: 'boss@corp.example',
      binding: 'b', client: TEST_CLIENT,
      link: { provider: 'google', subject: 'g-1', name: 'Boss' },
    });
    expect(mailer.last?.subject).toContain('привязки Google-аккаунта');
    // T22: имя Google-аккаунта задаёт тот, кто входит, — в письмо владельцу не попадает.
    expect(mailer.last?.text).not.toContain('Boss');
    await provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    expect(mailer.last?.subject).toContain('привязки Google-аккаунта');
    expect(mailer.last?.text).toContain('222222');
  });

  it('R20: обычная попытка — обычное письмо входа', async () => {
    const { mailer, provider } = make();
    await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    expect(mailer.last?.subject).toContain('код для входа');
  });
});
