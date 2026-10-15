import { describe, it, expect, beforeEach } from 'vitest';
import {
  EmailOwnershipRequiredError,
  IdentityService,
} from '../../../src/domain/identity/identity-service.js';
import { IdentityConflictError } from '../../../src/domain/identity/identity-repository.js';
import { InMemoryIdentityRepository } from '../../../src/adapters/repository/in-memory-identity-repository.js';
import { fakeClock } from '../../helpers/fake-clock.js';
import type { ProviderIdentity } from '../../../src/domain/identity/provider-identity.js';

function pid(overrides: Partial<ProviderIdentity> = {}): ProviderIdentity {
  return {
    provider: 'email',
    subject: 'alice@example.com',
    email: 'alice@example.com',
    emailVerified: true,
    profile: { name: 'Alice' },
    ...overrides,
  };
}

function usersCount(repo: InMemoryIdentityRepository): number {
  return (repo as unknown as { users: Map<string, unknown> }).users.size;
}

describe('IdentityService.resolveLogin', () => {
  let repo: InMemoryIdentityRepository;
  let service: IdentityService;

  beforeEach(() => {
    repo = new InMemoryIdentityRepository(
      fakeClock(new Date('2026-01-01T00:00:00.000Z')),
    );
    service = new IdentityService(repo);
  });

  it('создаёт нового пользователя при первом входе', async () => {
    const res = await service.resolveLogin(pid());
    expect(res.createdUser).toBe(true);
    expect(res.user.status).toBe('active');
  });

  it('повторный вход той же личностью возвращает того же пользователя', async () => {
    const first = await service.resolveLogin(pid());
    const second = await service.resolveLogin(pid());
    expect(second.createdUser).toBe(false);
    expect(second.linkedIdentity).toBe(false);
    expect(second.user.id).toBe(first.user.id);
  });

  it('связывает новую личность с существующим пользователем по подтверждённому email', async () => {
    const first = await service.resolveLogin(
      pid({ provider: 'google', subject: 'g-1' }),
    );
    const second = await service.resolveLogin(
      pid({ provider: 'email', subject: 'alice@example.com' }),
    );
    expect(second.user.id).toBe(first.user.id);
    expect(second.createdUser).toBe(false);
    expect(second.linkedIdentity).toBe(true);
  });

  it('новая личность с неподтверждённым адресом: ни присоединения, ни нового пользователя', async () => {
    const first = await service.resolveLogin(
      pid({ provider: 'email', subject: 'code:alice@example.com', emailVerified: true }),
    );
    await expect(
      service.resolveLogin(pid({ provider: 'google', subject: 'g-evil', emailVerified: false })),
    ).rejects.toBeInstanceOf(EmailOwnershipRequiredError);
    expect(await repo.findIdentity('google', 'g-evil')).toBeNull();
    expect(await repo.findUserByVerifiedEmail('alice@example.com')).toMatchObject({ id: first.user.id });
    expect(usersCount(repo)).toBe(1);
  });

  it('НЕ связывает, если у существующего (legacy) пользователя email не подтверждён', async () => {
    const legacy = await repo.createUser({});
    await repo.addIdentity({ userId: legacy.id, provider: 'email', subject: 'password:alice@example.com' });
    await repo.addEmail({ userId: legacy.id, email: 'alice@example.com', verified: false });
    const second = await service.resolveLogin(
      pid({ provider: 'google', subject: 'g-1', emailVerified: true }),
    );
    expect(second.user.id).not.toBe(legacy.id);
    expect(second.createdUser).toBe(true);
  });

  it('личность без email (ВК) → отдельный пользователь', async () => {
    const res = await service.resolveLogin(
      pid({ provider: 'vk', subject: 'vk-1', email: undefined, emailVerified: false }),
    );
    expect(res.createdUser).toBe(true);
  });

  it('связывание устойчиво к регистру и пробелам в email', async () => {
    const first = await service.resolveLogin(
      pid({ provider: 'google', subject: 'g-1', email: 'Alice@Example.com', emailVerified: true }),
    );
    const second = await service.resolveLogin(
      pid({ provider: 'email', subject: 'x', email: '  alice@example.com ', emailVerified: true }),
    );
    expect(second.user.id).toBe(first.user.id);
  });

  it('конфликт уникальности внутри единицы работы → откат и повтор целиком', async () => {
    const realAdd = repo.addIdentity.bind(repo);
    let failures = 1;
    repo.addIdentity = async (input) => {
      if (failures-- > 0) throw new IdentityConflictError();
      return realAdd(input);
    };
    const res = await service.resolveLogin(pid({ provider: 'vk', subject: 'vk-9', email: 'race@example.com' }));
    // Первая попытка откатилась: пользователь один, личность и почта на нём.
    expect(usersCount(repo)).toBe(1);
    expect((await repo.findIdentity('vk', 'vk-9'))?.userId).toBe(res.user.id);
    expect((await repo.findEmail(res.user.id, 'race@example.com'))?.verified).toBe(true);
  });

  it('сбой посреди первого входа не оставляет пользователя-сироту', async () => {
    repo.addIdentity = async () => {
      throw new Error('db down');
    };
    await expect(service.resolveLogin(pid({ provider: 'vk', subject: 'vk-1' }))).rejects.toThrow('db down');
    expect(usersCount(repo)).toBe(0);
    expect(await repo.findUserByVerifiedEmail('alice@example.com')).toBeNull();
  });

  it('F05: параллельные первые входы Google и кодом одним адресом → один пользователь', async () => {
    const [a, b] = await Promise.all([
      service.resolveLogin(pid({ provider: 'google', subject: 'g-1' })),
      service.resolveLogin(pid({ provider: 'email', subject: 'code:alice@example.com' })),
    ]);
    expect(a.user.id).toBe(b.user.id);
    expect(usersCount(repo)).toBe(1);
    expect([a.createdUser, b.createdUser].sort()).toEqual([false, true]);
  });

  it('адрес уже подтверждён у другого пользователя → вход не ломается, адрес неподтверждённый', async () => {
    const owner = await service.resolveLogin(pid({ provider: 'email', subject: 'code:alice@example.com' }));
    const other = await service.resolveLogin(
      pid({ provider: 'google', subject: 'g-2', email: 'bob@example.com' }),
    );
    // Google-аккаунт bob сменил почту на занятую alice@example.com.
    const again = await service.resolveLogin(pid({ provider: 'google', subject: 'g-2', email: 'alice@example.com' }));
    expect(again.user.id).toBe(other.user.id);
    expect((await repo.findEmail(other.user.id, 'alice@example.com'))?.verified).toBe(false);
    expect((await repo.findUserByVerifiedEmail('alice@example.com'))?.id).toBe(owner.user.id);
  });

  it('подтверждает ранее неподтверждённый email того же пользователя', async () => {
    const legacy = await repo.createUser({});
    await repo.addIdentity({ userId: legacy.id, provider: 'email', subject: 'code:alice@example.com' });
    await repo.addEmail({ userId: legacy.id, email: 'alice@example.com', verified: false });
    await service.resolveLogin(
      pid({ provider: 'email', subject: 'code:alice@example.com', emailVerified: true }),
    );
    const email = await repo.findEmail(legacy.id, 'alice@example.com');
    expect(email?.verified).toBe(true);
  });
});

// R01: адрес и его статус для id_token и SSO-сессии берутся из базы после
// записи, а не из ответа провайдера.
describe('IdentityService.resolveLogin: адрес входа по состоянию базы', () => {
  let repo: InMemoryIdentityRepository;
  let service: IdentityService;

  beforeEach(() => {
    repo = new InMemoryIdentityRepository(fakeClock(new Date('2026-01-01T00:00:00.000Z')));
    service = new IdentityService(repo);
  });

  it('обычный вход: подтверждённый адрес этого входа', async () => {
    const res = await service.resolveLogin(pid());
    expect(res.email).toBe('alice@example.com');
    expect(res.emailVerified).toBe(true);
  });

  it('привязанный Google принёс новый адрес без доказанного владения → прежний подтверждённый адрес', async () => {
    const first = await service.resolveLogin(pid({ provider: 'google', subject: 'g-1' }));
    const again = await service.resolveLogin(
      pid({ provider: 'google', subject: 'g-1', email: 'new@other.example', emailVerified: false }),
    );
    expect(again.user.id).toBe(first.user.id);
    expect(again.email).toBe('alice@example.com');
    expect(again.emailVerified).toBe(true);
    expect((await repo.findEmail(first.user.id, 'new@other.example'))?.verified).toBe(false);
  });

  it('адрес подтверждён у другого пользователя → в снимок уходит прежний адрес, не чужой', async () => {
    await service.resolveLogin(pid({ provider: 'email', subject: 'code:victim@corp.example', email: 'victim@corp.example' }));
    const a = await service.resolveLogin(pid({ provider: 'google', subject: 'g-a', email: 'a@corp.example' }));
    const again = await service.resolveLogin(
      pid({ provider: 'google', subject: 'g-a', email: 'victim@corp.example', emailVerified: true }),
    );
    expect(again.user.id).toBe(a.user.id);
    expect(again.email).toBe('a@corp.example');
    expect(again.emailVerified).toBe(true);
  });

  it('подтверждённых адресов у пользователя нет → адрес входа с email_verified=false', async () => {
    const legacy = await repo.createUser({});
    await repo.addIdentity({ userId: legacy.id, provider: 'google', subject: 'g-legacy' });
    const res = await service.resolveLogin(
      pid({ provider: 'google', subject: 'g-legacy', email: 'x@other.example', emailVerified: false }),
    );
    expect(res.email).toBe('x@other.example');
    expect(res.emailVerified).toBe(false);
  });
});
