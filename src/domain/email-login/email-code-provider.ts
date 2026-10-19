import { createHash, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import type { Clock } from '../../ports/clock.js';
import { MailDeliveryError, type Mailer } from '../../ports/mailer.js';
import type { IdentityProvider, ProviderIdentity } from '../identity/provider-identity.js';
import { parseEmailAddress } from '../identity/user.js';
import { sha256Hex } from '../shared/hash.js';
import {
  ChallengeClientChangedError,
  InvalidCredentialsError,
  InvalidEmailError,
  UnconfirmedCodeDeliveryError,
} from './errors.js';
import { codeIdentity } from './email-provider.js';
import type { ChallengeClient, LoginChallengeRecord, LoginChallengeStore, PendingLink } from './login-challenge.js';
import { buildGoogleLinkCodeEmail, buildLoginCodeEmail } from '../../adapters/mail/templates.js';

export interface EmailCodeProviderOptions {
  appName: string;
  codeTtlMinutes: number;
  // Проверок кода на одну попытку входа и переотправок в её рамках.
  maxAttempts?: number;
  maxResends?: number;
  // Только для тестов: детерминированный код вместо случайного 6-значного.
  generateCode?: () => string;
}

export interface StartedChallenge {
  handle: string; // отдаётся браузеру скрытым полем формы
  email: string;
}

export interface ChallengeView {
  email: string;
  link: PendingLink | null;
  // Попытка начата у этой регистрации клиента (и после миграции 0014).
  startedFor: (client: ChallengeClient) => boolean;
  attemptsLeft: number;
  resendsLeft: number;
}

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_MAX_RESENDS = 3;

const verifySchema = z.object({
  handle: z.string().min(1),
  binding: z.string().min(1),
  code: z.string().min(1),
  client: z.object({ id: z.string().min(1), registrationId: z.string().optional() }),
});

// Попытка продолжается только у той регистрации клиента, у которой начата.
function sameClient(record: LoginChallengeRecord, client: ChallengeClient): boolean {
  return record.clientId === client.id && record.clientRegistrationId === (client.registrationId ?? null);
}

function randomNumericCode(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, '0');
}

function hashCode(handle: string, code: string): string {
  return createHash('sha256').update(`otp:${handle}:${code}`).digest('hex');
}

function hashHandle(handle: string): string {
  return sha256Hex(`challenge:${handle}`);
}

// Привязка к браузеру: значение csrf-cookie. Хешируем отдельным префиксом.
export function bindingHashOf(binding: string): string {
  return sha256Hex(`binding:${binding}`);
}

function sameHash(storedHex: string, presentedHex: string): boolean {
  const a = Buffer.from(storedHex, 'hex');
  const b = Buffer.from(presentedHex, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

// Результат верного кода: личность почты и, если попытка была начата входом
// через Google со сторонним адресом, личность для отложенной привязки.
export interface VerifiedChallenge {
  identity: ProviderIdentity;
  link: PendingLink | null;
}

export class EmailCodeProvider implements IdentityProvider {
  readonly id = 'email-code';
  private readonly maxAttempts: number;
  private readonly maxResends: number;
  private readonly generateCode: () => string;

  constructor(
    private readonly store: LoginChallengeStore,
    private readonly mailer: Mailer,
    private readonly clock: Clock,
    private readonly opts: EmailCodeProviderOptions,
  ) {
    this.maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.maxResends = opts.maxResends ?? DEFAULT_MAX_RESENDS;
    this.generateCode = opts.generateCode ?? randomNumericCode;
  }

  private ttlMs(): number {
    return this.opts.codeTtlMinutes * 60_000;
  }

  // Новая независимая попытка входа: свой handle, свой код, свой лимит проверок.
  // Адрес проверяется строго ДО обращения к почте. Письмо не подтвердилось —
  // попытку не бросаем: UnconfirmedCodeDeliveryError отдаёт её handle.
  // Провайдер отказал — попытка гасится, наружу исходная MailDeliveryError.
  async start(input: {
    email: string;
    binding: string;
    client: ChallengeClient;
    link?: PendingLink;
  }): Promise<StartedChallenge> {
    const email = parseEmailAddress(input.email);
    if (!email) throw new InvalidEmailError();
    const handle = randomBytes(32).toString('base64url');
    const code = this.generateCode();
    const now = this.clock.now();
    const id = randomUUID();
    await this.store.create({
      id,
      handleHash: hashHandle(handle),
      bindingHash: bindingHashOf(input.binding),
      email,
      clientId: input.client.id,
      clientRegistrationId: input.client.registrationId ?? null,
      codeHash: hashCode(handle, code),
      attempts: 0,
      maxAttempts: this.maxAttempts,
      resends: 0,
      maxResends: this.maxResends,
      link: input.link ?? null,
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.ttlMs()),
      consumedAt: null,
    });
    try {
      await this.sendCode(email, code, input.link ?? null);
    } catch (err) {
      if (!(err instanceof MailDeliveryError)) throw err;
      if (err.outcome === 'unconfirmed') throw new UnconfirmedCodeDeliveryError({ handle, email }, err);
      // Провайдер отказал: письма не будет, попытку гасим.
      await this.store.consume(id, this.clock.now());
      throw err;
    }
    return { handle, email };
  }

  // Переотправка в рамках той же попытки. Слот берётся атомарно до письма:
  // параллельные запросы не отправят больше maxResends писем. Письмо ушло —
  // код заменяется, прежний перестаёт действовать сразу. Письмо не ушло —
  // слот возвращается, прежний код действует. null — попытки нет/исчерпана,
  // нужен новый вход (в том числе если её погасили, пока уходило письмо).
  // Попытка другой регистрации клиента — ChallengeClientChangedError, письма нет.
  async resend(input: { handle: string; binding: string; client: ChallengeClient }): Promise<{ email: string } | null> {
    const handleHash = hashHandle(input.handle);
    const bindingHash = bindingHashOf(input.binding);
    const current = await this.store.find(handleHash, bindingHash, this.clock.now());
    if (!current) return null;
    if (!sameClient(current, input.client)) throw new ChallengeClientChangedError();
    const reserved = await this.store.reserveResend(handleHash, bindingHash, this.clock.now());
    if (!reserved) return null;
    const code = this.generateCode();
    try {
      await this.sendCode(reserved.email, code, reserved.link);
    } catch (err) {
      await this.store.releaseResend(reserved.id);
      throw err;
    }
    const now = this.clock.now();
    const replaced = await this.store.replaceCode(
      reserved.id,
      hashCode(input.handle, code),
      new Date(now.getTime() + this.ttlMs()),
      now,
    );
    return replaced ? { email: reserved.email } : null;
  }

  async describe(input: { handle: string; binding: string }): Promise<ChallengeView | null> {
    const record = await this.store.find(
      hashHandle(input.handle),
      bindingHashOf(input.binding),
      this.clock.now(),
    );
    if (!record) return null;
    return {
      email: record.email,
      link: record.link,
      startedFor: (client) => sameClient(record, client),
      attemptsLeft: record.maxAttempts - record.attempts,
      resendsLeft: record.maxResends - record.resends,
    };
  }

  // Проверка кода. Сначала атомарно занимаем проверку (лимит не обойти
  // параллельными запросами), затем сверяем клиента и код, при совпадении
  // гасим CAS. Попытка другой регистрации клиента не гасится и кода не выдаёт.
  async verifyChallenge(input: {
    handle: string;
    binding: string;
    code: string;
    client: ChallengeClient;
  }): Promise<VerifiedChallenge> {
    const { handle, binding, code, client } = verifySchema.parse(input);
    const now = this.clock.now();
    const record = await this.store.claimAttempt(hashHandle(handle), bindingHashOf(binding), now);
    if (!record) throw new InvalidCredentialsError();
    if (!sameClient(record, client)) throw new ChallengeClientChangedError();
    if (!sameHash(record.codeHash, hashCode(handle, code.trim()))) throw new InvalidCredentialsError();
    if (!(await this.store.consume(record.id, now))) throw new InvalidCredentialsError();
    return { identity: codeIdentity(record.email), link: record.link };
  }

  // IdentityProvider: credential = { handle, binding, code, client }.
  async verify(credential: unknown): Promise<ProviderIdentity> {
    return (await this.verifyChallenge(verifySchema.parse(credential))).identity;
  }

  // Попытка привязки Google — отдельное письмо: код подтверждает привязку,
  // а не обычный вход.
  private async sendCode(email: string, code: string, link: PendingLink | null): Promise<void> {
    const opts = { to: email, code, ttlMinutes: this.opts.codeTtlMinutes, appName: this.opts.appName };
    await this.mailer.send(link ? buildGoogleLinkCodeEmail(opts) : buildLoginCodeEmail(opts));
  }
}
