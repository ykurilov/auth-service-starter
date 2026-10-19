import { describe, it, expect, beforeEach } from 'vitest';
import { InMemoryIdentityRepository } from '../../../src/adapters/repository/in-memory-identity-repository.js';
import { fakeClock } from '../../helpers/fake-clock.js';

describe('InMemoryIdentityRepository', () => {
  let repo: InMemoryIdentityRepository;

  beforeEach(() => {
    repo = new InMemoryIdentityRepository(
      fakeClock(new Date('2026-01-01T00:00:00.000Z')),
    );
  });

  it('createUser возвращает активного пользователя с id и createdAt от часов', async () => {
    const user = await repo.createUser({ displayName: 'Alice' });
    expect(user.id).toBeTruthy();
    expect(user.status).toBe('active');
    expect(user.displayName).toBe('Alice');
    expect(user.createdAt.toISOString()).toBe('2026-01-01T00:00:00.000Z');
    expect(await repo.findUserById(user.id)).toEqual(user);
  });

  it('fillDisplayName заполняет только пустое имя', async () => {
    const empty = await repo.createUser({});
    await repo.fillDisplayName(empty.id, 'Иван');
    expect((await repo.findUserById(empty.id))?.displayName).toBe('Иван');
    await repo.fillDisplayName(empty.id, 'Пётр');
    expect((await repo.findUserById(empty.id))?.displayName).toBe('Иван');
  });

  it('addIdentity + findIdentity — round-trip по (provider, subject)', async () => {
    const user = await repo.createUser({});
    await repo.addIdentity({ userId: user.id, provider: 'google', subject: 'g-1' });
    const found = await repo.findIdentity('google', 'g-1');
    expect(found?.userId).toBe(user.id);
    expect(await repo.findIdentity('google', 'missing')).toBeNull();
  });

  it('findUserByVerifiedEmail находит только подтверждённые адреса', async () => {
    const user = await repo.createUser({});
    await repo.addEmail({ userId: user.id, email: 'A@B.com', verified: false });
    expect(await repo.findUserByVerifiedEmail('a@b.com')).toBeNull();

    const email = await repo.findEmail(user.id, 'a@b.com');
    expect(email).not.toBeNull();
    await repo.markEmailVerified(email!.id);
    expect((await repo.findUserByVerifiedEmail('a@b.com'))?.id).toBe(user.id);
  });

  it('findEmail нормализует адрес', async () => {
    const user = await repo.createUser({});
    await repo.addEmail({ userId: user.id, email: 'user@mail.ru', verified: true });
    expect(await repo.findEmail(user.id, '  User@Mail.RU ')).not.toBeNull();
  });

  it('findEmailsForUser возвращает адреса юзера и пусто для чужого', async () => {
    const user = await repo.createUser({});
    const other = await repo.createUser({});
    await repo.addEmail({ userId: user.id, email: 'a@b.com', verified: true });
    await repo.addEmail({ userId: user.id, email: 'c@d.com', verified: false });

    const emails = await repo.findEmailsForUser(user.id);
    expect(emails.map((e) => e.email).sort()).toEqual(['a@b.com', 'c@d.com']);
    expect(await repo.findEmailsForUser(other.id)).toEqual([]);
  });
});
