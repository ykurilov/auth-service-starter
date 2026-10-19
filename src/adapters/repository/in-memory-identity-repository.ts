import { randomUUID } from 'node:crypto';
import type { Clock } from '../../ports/clock.js';
import { systemClock } from '../../ports/clock.js';
import {
  IdentityConflictError,
  type IdentityRepository,
} from '../../domain/identity/identity-repository.js';
import type { User, Identity, EmailAddress } from '../../domain/identity/user.js';
import { normalizeEmail } from '../../domain/identity/user.js';

export class InMemoryIdentityRepository implements IdentityRepository {
  private users = new Map<string, User>();
  private identities: Identity[] = [];
  private emails: EmailAddress[] = [];
  // Очередь единиц работы runAtomic: одна на хранилище (in-memory — dev и
  // тесты, один процесс), поэтому откат снимком не затирает чужих записей.
  private atomicQueue: Promise<unknown> = Promise.resolve();

  constructor(private readonly clock: Clock = systemClock) {}

  // Возвращаем копии, а не ссылки на внутренние объекты: реальная БД отдаёт
  // свежие строки, и мутация результата не должна портить состояние хранилища.
  private static copy<T>(value: T): T {
    return { ...value };
  }

  // Эталон контракта runAtomic: строго по очереди и с откатом к снимку при
  // ошибке — как транзакция Postgres, ни одна запись сбойной единицы не остаётся.
  async runAtomic<T>(
    _lockKeys: string[],
    fn: (repo: IdentityRepository) => Promise<T>,
  ): Promise<T> {
    const run = async (): Promise<T> => {
      const snapshot = {
        users: new Map([...this.users].map(([k, v]) => [k, { ...v }])),
        identities: this.identities.map((i) => ({ ...i })),
        emails: this.emails.map((e) => ({ ...e })),
      };
      try {
        return await fn(this);
      } catch (err) {
        this.users = snapshot.users;
        this.identities = snapshot.identities;
        this.emails = snapshot.emails;
        throw err;
      }
    };
    const result = this.atomicQueue.then(run, run);
    this.atomicQueue = result.catch(() => undefined);
    return result;
  }

  async findUserById(id: string): Promise<User | null> {
    const user = this.users.get(id);
    return user ? InMemoryIdentityRepository.copy(user) : null;
  }

  async findIdentity(provider: string, subject: string): Promise<Identity | null> {
    const identity = this.identities.find(
      (i) => i.provider === provider && i.subject === subject,
    );
    return identity ? InMemoryIdentityRepository.copy(identity) : null;
  }

  async findUserByVerifiedEmail(email: string): Promise<User | null> {
    const normalized = normalizeEmail(email);
    const match = this.emails.find(
      (e) => e.email === normalized && e.verified,
    );
    if (!match) return null;
    const user = this.users.get(match.userId);
    return user ? InMemoryIdentityRepository.copy(user) : null;
  }

  async createUser(data: { displayName?: string }): Promise<User> {
    const user: User = {
      id: randomUUID(),
      displayName: data.displayName,
      status: 'active',
      createdAt: this.clock.now(),
    };
    this.users.set(user.id, user);
    return InMemoryIdentityRepository.copy(user);
  }

  async addIdentity(data: {
    userId: string;
    provider: string;
    subject: string;
  }): Promise<Identity> {
    if (this.identities.some((i) => i.provider === data.provider && i.subject === data.subject)) {
      throw new IdentityConflictError(`личность уже привязана: ${data.provider}`);
    }
    const identity: Identity = {
      id: randomUUID(),
      userId: data.userId,
      provider: data.provider,
      subject: data.subject,
      createdAt: this.clock.now(),
    };
    this.identities.push(identity);
    return InMemoryIdentityRepository.copy(identity);
  }

  async addEmail(data: {
    userId: string;
    email: string;
    verified: boolean;
  }): Promise<EmailAddress> {
    const normalized = normalizeEmail(data.email);
    // Паритет с pg-ограничениями: unique(user_id, email) и partial-unique на
    // verified email. Молчаливый push скрывал бы гонки линковки от тестов.
    if (this.emails.some((e) => e.userId === data.userId && e.email === normalized)) {
      throw new IdentityConflictError(`email уже привязан к пользователю: ${normalized}`);
    }
    if (data.verified && this.emails.some((e) => e.email === normalized && e.verified)) {
      throw new IdentityConflictError(`verified email уже занят другим пользователем: ${normalized}`);
    }
    const email: EmailAddress = {
      id: randomUUID(),
      userId: data.userId,
      email: normalized,
      verified: data.verified,
      createdAt: this.clock.now(),
    };
    this.emails.push(email);
    return InMemoryIdentityRepository.copy(email);
  }

  async findEmail(userId: string, email: string): Promise<EmailAddress | null> {
    const normalized = normalizeEmail(email);
    const found = this.emails.find(
      (e) => e.userId === userId && e.email === normalized,
    );
    return found ? InMemoryIdentityRepository.copy(found) : null;
  }

  async findEmailsForUser(userId: string): Promise<EmailAddress[]> {
    return this.emails
      .filter((e) => e.userId === userId)
      .map((e) => InMemoryIdentityRepository.copy(e));
  }

  async fillDisplayName(userId: string, name: string): Promise<void> {
    const user = this.users.get(userId);
    if (user && user.displayName === undefined) user.displayName = name;
  }

  async markEmailVerified(emailId: string): Promise<void> {
    const email = this.emails.find((e) => e.id === emailId);
    if (email) email.verified = true;
  }
}
