import { describe, it, expect, vi } from 'vitest';
import { EmailCodeProvider, bindingHashOf } from '../../../src/domain/email-login/email-code-provider.js';
import { InMemoryLoginChallengeStore } from '../../../src/adapters/repository/in-memory-login-challenge-store.js';
import { FakeMailer } from '../../../src/adapters/mail/fake-mailer.js';
import {
  ChallengeClientChangedError,
  InvalidCredentialsError,
  InvalidEmailError,
  UnconfirmedCodeDeliveryError,
} from '../../../src/domain/email-login/errors.js';
import type { OutgoingEmail } from '../../../src/ports/mailer.js';
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

  it('T08: провайдер отказал при переотправке — прежний код действует, переотправка не списана', async () => {
    const { provider, mailer } = make(['111111', '222222', '333333']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    const send = mailer.send.bind(mailer);
    mailer.send = async () => { throw new MailDeliveryError('422', 'rejected'); };
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

  // Письмо уходит только по команде теста: так задаётся порядок, в котором
  // провайдер отвечает на параллельные переотправки.
  function holdSends(mailer: FakeMailer) {
    const held: { email: OutgoingEmail; deliver: () => void; fail: (err: Error) => void }[] = [];
    mailer.send = (email) =>
      new Promise<void>((resolve, reject) => {
        held.push({ email, deliver: () => { mailer.sent.push(email); resolve(); }, fail: reject });
      });
    return held;
  }
  const codeOf = (email: OutgoingEmail) => /\d{6}/.exec(email.text)![0];

  it('R4-A1: таймаут переотправки — слот не возвращается, действует код этого письма', async () => {
    const { provider, mailer } = make(['111111', '222222']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    const send = mailer.send.bind(mailer);
    mailer.send = async (email) => { await send(email); throw new MailDeliveryError('timeout'); };
    const err = await provider.resend({ handle, binding: 'b', client: TEST_CLIENT }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(UnconfirmedCodeDeliveryError);
    expect((err as UnconfirmedCodeDeliveryError).challenge).toEqual({ handle, email: 'a@b.com' });
    expect(await provider.describe({ handle, binding: 'b' })).toMatchObject({ resendsLeft: 2 });
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '111111' })).rejects.toBeInstanceOf(InvalidCredentialsError);
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '222222' })).resolves.toBeTruthy();
  });

  it('R4-A1: таймауты не обходят лимит трёх переотправок', async () => {
    const { provider, mailer } = make(['100000', '200000', '300000', '400000', '500000']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    const send = mailer.send.bind(mailer);
    mailer.send = async (email) => { await send(email); throw new MailDeliveryError('timeout'); };
    for (let i = 0; i < 3; i++) {
      await expect(provider.resend({ handle, binding: 'b', client: TEST_CLIENT })).rejects.toBeInstanceOf(UnconfirmedCodeDeliveryError);
    }
    expect(await provider.resend({ handle, binding: 'b', client: TEST_CLIENT })).toBeNull();
    expect(mailer.sent).toHaveLength(4);
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: '400000' })).resolves.toBeTruthy();
  });

  it('R4-A2: опоздавшее письмо более раннего слота не затирает код более нового', async () => {
    const { provider, mailer } = make(['111111', '222222', '333333']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    const held = holdSends(mailer);
    const first = provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    await vi.waitFor(() => expect(held).toHaveLength(1));
    const second = provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    await vi.waitFor(() => expect(held).toHaveLength(2));
    held[1]!.deliver();
    expect(await second).toEqual({ email: 'a@b.com' });
    held[0]!.deliver();
    expect(await first).toEqual({ email: 'a@b.com' });
    const [older, newer] = [codeOf(held[0]!.email), codeOf(held[1]!.email)];
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: older })).rejects.toBeInstanceOf(InvalidCredentialsError);
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: newer })).resolves.toBeTruthy();
  });

  it('R4-A2: отказ провайдера по новому слоту оставляет код более раннего письма', async () => {
    const { provider, mailer } = make(['111111', '222222', '333333']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    const held = holdSends(mailer);
    const first = provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    await vi.waitFor(() => expect(held).toHaveLength(1));
    const second = provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    await vi.waitFor(() => expect(held).toHaveLength(2));
    held[1]!.fail(new MailDeliveryError('422', 'rejected'));
    await expect(second).rejects.toBeInstanceOf(MailDeliveryError);
    held[0]!.deliver();
    await first;
    expect(await provider.describe({ handle, binding: 'b' })).toMatchObject({ resendsLeft: 2 });
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: codeOf(held[0]!.email) })).resolves.toBeTruthy();
  });

  it('R4-A2: слот, возвращённый после отказа, не получает номер уже действующего кода', async () => {
    const { provider, mailer } = make(['111111', '222222', '333333', '444444']);
    const { handle } = await provider.start({ email: 'a@b.com', binding: 'b', client: TEST_CLIENT });
    const held = holdSends(mailer);
    const first = provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    await vi.waitFor(() => expect(held).toHaveLength(1));
    const second = provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    await vi.waitFor(() => expect(held).toHaveLength(2));
    held[1]!.deliver();
    await second;
    held[0]!.fail(new MailDeliveryError('422', 'rejected'));
    await expect(first).rejects.toBeInstanceOf(MailDeliveryError);
    // Слот вернулся, и следующая переотправка — новее действующего кода.
    const third = provider.resend({ handle, binding: 'b', client: TEST_CLIENT });
    await vi.waitFor(() => expect(held).toHaveLength(3));
    held[2]!.deliver();
    expect(await third).toEqual({ email: 'a@b.com' });
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: codeOf(held[1]!.email) })).rejects.toBeInstanceOf(InvalidCredentialsError);
    await expect(provider.verify({ handle, binding: 'b', client: TEST_CLIENT, code: codeOf(held[2]!.email) })).resolves.toBeTruthy();
  });
});

describe('R5: resume — возврат браузера к своей живой попытке', () => {
  const OTHER_REGISTRATION = { id: 'app', registrationId: '00000000-0000-4000-8000-000000000002' };

  it('тот же браузер, адрес и клиент: тот же handle, письма нет, код из первого письма подходит', async () => {
    const { mailer, provider } = make(['111111']);
    const started = await provider.start({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT });
    const resumed = await provider.resume({ email: ' U@X.com ', binding: 'b', client: TEST_CLIENT });
    expect(resumed).toEqual(started);
    expect(mailer.sent).toHaveLength(1);
    expect((await provider.verify({ handle: resumed!.handle, binding: 'b', client: TEST_CLIENT, code: '111111' })).email).toBe('u@x.com');
  });

  it('берёт последнюю живую попытку', async () => {
    const { provider, clock } = make();
    await provider.start({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT });
    clock.advance(1);
    const latest = await provider.start({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT });
    expect((await provider.resume({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT }))?.handle).toBe(latest.handle);
  });

  it('другой браузер, адрес, регистрация клиента или привязка Google — null', async () => {
    const { provider } = make();
    await provider.start({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT });
    expect(await provider.resume({ email: 'u@x.com', binding: 'other', client: TEST_CLIENT })).toBeNull();
    expect(await provider.resume({ email: 'v@x.com', binding: 'b', client: TEST_CLIENT })).toBeNull();
    expect(await provider.resume({ email: 'u@x.com', binding: 'b', client: OTHER_REGISTRATION })).toBeNull();
    expect(await provider.resume({ email: 'u@x.com', binding: 'b', client: { id: 'app' } })).toBeNull();
    const link = { provider: 'google', subject: 'g-1' };
    expect(await provider.resume({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT, link })).toBeNull();
    await provider.start({ email: 'g@x.com', binding: 'b', client: TEST_CLIENT, link });
    expect(await provider.resume({ email: 'g@x.com', binding: 'b', client: TEST_CLIENT })).toBeNull();
    expect(await provider.resume({ email: 'g@x.com', binding: 'b', client: TEST_CLIENT, link: { ...link, subject: 'g-2' } })).toBeNull();
    expect(await provider.resume({ email: 'g@x.com', binding: 'b', client: TEST_CLIENT, link })).not.toBeNull();
  });

  it('погашенная, истёкшая или без проверок попытка — null', async () => {
    const { provider, clock } = make(['111111']);
    const done = await provider.start({ email: 'a@x.com', binding: 'b', client: TEST_CLIENT });
    await provider.verify({ handle: done.handle, binding: 'b', client: TEST_CLIENT, code: '111111' });
    expect(await provider.resume({ email: 'a@x.com', binding: 'b', client: TEST_CLIENT })).toBeNull();
    const spent = await provider.start({ email: 'c@x.com', binding: 'b', client: TEST_CLIENT });
    for (let i = 0; i < 5; i++)
      await provider.verify({ handle: spent.handle, binding: 'b', client: TEST_CLIENT, code: '000000' }).catch(() => undefined);
    expect(await provider.resume({ email: 'c@x.com', binding: 'b', client: TEST_CLIENT })).toBeNull();
    await provider.start({ email: 'e@x.com', binding: 'b', client: TEST_CLIENT });
    clock.advance(15 * 60);
    expect(await provider.resume({ email: 'e@x.com', binding: 'b', client: TEST_CLIENT })).toBeNull();
  });

  it('попытка, начатая со случайным handle (до обновления), не подхватывается', async () => {
    const { store, provider } = make();
    await store.create({
      id: 'legacy', handleHash: 'h', bindingHash: bindingHashOf('b'), email: 'u@x.com',
      clientId: TEST_CLIENT.id, clientRegistrationId: TEST_CLIENT.registrationId, codeHash: 'c',
      attempts: 0, maxAttempts: 5, resends: 0, maxResends: 3, lastSlot: 0, codeSlot: 0, link: null,
      createdAt: T0, expiresAt: new Date(T0.getTime() + 15 * 60_000), consumedAt: null,
    });
    expect(await provider.resume({ email: 'u@x.com', binding: 'b', client: TEST_CLIENT })).toBeNull();
  });
});
