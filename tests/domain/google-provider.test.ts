import { describe, it, expect } from 'vitest';
import {
  GoogleProvider,
  isGoogleAuthoritativeEmail,
  type GoogleTokenPayload,
} from '../../src/domain/google-login/google-provider.js';
import { GoogleNonceService } from '../../src/domain/google-login/google-nonce.js';
import { InMemoryGoogleNonceStore } from '../../src/adapters/repository/in-memory-google-nonce-store.js';
import { InvalidCredentialsError } from '../../src/domain/email-login/errors.js';
import { advanceableClock } from '../helpers/advanceable-clock.js';

const BINDING = 'browser-csrf';
const CLIENT = 'app';

async function setup(over: Partial<GoogleTokenPayload> = {}, issueFor = { binding: BINDING, clientId: CLIENT }) {
  const clock = advanceableClock(new Date('2026-07-01T00:00:00Z'));
  const nonces = new GoogleNonceService(new InMemoryGoogleNonceStore(), clock, 600);
  const nonce = await nonces.issue(issueFor.binding, issueFor.clientId);
  const payload: GoogleTokenPayload = {
    sub: 'g-123',
    email: 'user@gmail.com',
    emailVerified: true,
    name: 'Юрий',
    avatarUrl: 'https://lh3.example/pic',
    nonce,
    ...over,
  };
  const provider = new GoogleProvider({ verify: async () => payload }, nonces);
  return { provider, clock, nonce };
}

const cred = (over: Record<string, unknown> = {}) => ({
  credential: 'token',
  binding: BINDING,
  clientId: CLIENT,
  ...over,
});

describe('GoogleProvider', () => {
  it('gmail-адрес с серверным nonce → личность google, владение доказано', async () => {
    const { provider } = await setup();
    expect(await provider.verify(cred())).toEqual({
      provider: 'google',
      subject: 'g-123',
      email: 'user@gmail.com',
      emailVerified: true,
      profile: { name: 'Юрий', avatarUrl: 'https://lh3.example/pic' },
    });
  });

  it('nonce одноразовый: второй verify того же токена → InvalidCredentialsError', async () => {
    const { provider } = await setup();
    await provider.verify(cred());
    await expect(provider.verify(cred())).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('nonce другого браузера или клиента → InvalidCredentialsError', async () => {
    const { provider } = await setup();
    await expect(provider.verify(cred({ binding: 'other' }))).rejects.toBeInstanceOf(InvalidCredentialsError);
    await expect(provider.verify(cred({ clientId: 'app2' }))).rejects.toBeInstanceOf(InvalidCredentialsError);
    // Неудачные предъявления не погасили nonce законного браузера.
    await expect(provider.verify(cred())).resolves.toBeTruthy();
  });

  it('просроченный nonce → InvalidCredentialsError', async () => {
    const { provider, clock } = await setup();
    clock.advance(601);
    await expect(provider.verify(cred())).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('токен без nonce или с невыпущенным nonce → InvalidCredentialsError', async () => {
    await expect((await setup({ nonce: undefined })).provider.verify(cred())).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
    await expect((await setup({ nonce: 'made-up' })).provider.verify(cred())).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
  });

  it('почта не подтверждена Google или отсутствует → InvalidCredentialsError', async () => {
    await expect((await setup({ emailVerified: false })).provider.verify(cred())).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
    await expect((await setup({ email: undefined })).provider.verify(cred())).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
  });

  it('ошибка проверки подписи → InvalidCredentialsError, не 500-я ошибка', async () => {
    const clock = advanceableClock(new Date('2026-07-01T00:00:00Z'));
    const provider = new GoogleProvider(
      { verify: async () => { throw new Error('bad signature'); } },
      new GoogleNonceService(new InMemoryGoogleNonceStore(), clock),
    );
    await expect(provider.verify(cred())).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it('R01: сторонний адрес без hd → emailVerified:false (владение не доказано)', async () => {
    const { provider } = await setup({ email: 'boss@corp.example' });
    expect((await provider.verify(cred())).emailVerified).toBe(false);
  });

  it('R01: hd совпадает с доменом адреса → владение доказано; hd чужого домена — нет', async () => {
    expect((await (await setup({ email: 'boss@corp.example', hd: 'corp.example' })).provider.verify(cred())).emailVerified).toBe(true);
    expect((await (await setup({ email: 'boss@corp.example', hd: 'evil.example' })).provider.verify(cred())).emailVerified).toBe(false);
  });

  it('адрес из токена проходит строгую проверку (без отображаемого имени)', async () => {
    const { provider } = await setup({ email: 'x@gmail.com <y@evil.example>' });
    await expect(provider.verify(cred())).rejects.toBeInstanceOf(InvalidCredentialsError);
  });
});

describe('isGoogleAuthoritativeEmail', () => {
  it.each([
    ['a@gmail.com', undefined, true],
    ['a@GMAIL.com', undefined, true],
    ['a@googlemail.com', undefined, false],
    ['a@corp.example', undefined, false],
    ['a@corp.example', 'corp.example', true],
    ['a@corp.example', 'CORP.example', true],
    ['a@sub.corp.example', 'corp.example', false],
    ['a@corp.example', '', false],
  ])('%s, hd=%s → %s', (email, hd, expected) => {
    expect(isGoogleAuthoritativeEmail(email, hd)).toBe(expected);
  });
});
