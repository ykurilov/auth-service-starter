import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMemDb } from '../../../helpers/pg-mem-db.js';
import { runMigrations } from '../../../../src/adapters/db/migrate.js';
import type { Db } from '../../../../src/adapters/db/pool.js';
import { PgIdentityRepository } from '../../../../src/adapters/repository/pg/pg-identity-repository.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../migrations',
);

describe('PgIdentityRepository на pg-mem', () => {
  let db: Db;
  let repo: PgIdentityRepository;

  beforeEach(async () => {
    db = createMemDb();
    await runMigrations(db, migrationsDir);
    repo = new PgIdentityRepository(db);
  });

  afterEach(async () => {
    await db.close();
  });

  it('createUser -> findUserById round-trip', async () => {
    const user = await repo.createUser({ displayName: 'Alice' });
    expect(user.id).toBeTruthy();
    expect(user.status).toBe('active');
    expect(user.displayName).toBe('Alice');
    expect(user.createdAt).toBeInstanceOf(Date);

    const found = await repo.findUserById(user.id);
    expect(found).toEqual(user);
  });

  it('fillDisplayName заполняет только пустое имя', async () => {
    const empty = await repo.createUser({});
    await repo.fillDisplayName(empty.id, 'Иван');
    expect((await repo.findUserById(empty.id))?.displayName).toBe('Иван');
    await repo.fillDisplayName(empty.id, 'Пётр');
    expect((await repo.findUserById(empty.id))?.displayName).toBe('Иван');
  });

  it('findUserById неизвестного -> null', async () => {
    expect(await repo.findUserById('00000000-0000-0000-0000-000000000000')).toBeNull();
  });

  it('addIdentity -> findIdentity по (provider, subject)', async () => {
    const user = await repo.createUser({});
    const identity = await repo.addIdentity({
      userId: user.id,
      provider: 'google',
      subject: 'g-1',
    });
    expect(identity.id).toBeTruthy();
    expect(identity.userId).toBe(user.id);

    const found = await repo.findIdentity('google', 'g-1');
    expect(found).toEqual(identity);
    expect(await repo.findIdentity('google', 'missing')).toBeNull();
  });

  it('addEmail(verified) -> findUserByVerifiedEmail', async () => {
    const user = await repo.createUser({});
    await repo.addEmail({ userId: user.id, email: 'A@B.com', verified: true });

    const found = await repo.findUserByVerifiedEmail('a@b.com');
    expect(found?.id).toBe(user.id);
    expect(await repo.findUserByVerifiedEmail('missing@x.com')).toBeNull();
  });

  it('неверифицированный email не находится через findUserByVerifiedEmail', async () => {
    const user = await repo.createUser({});
    await repo.addEmail({ userId: user.id, email: 'a@b.com', verified: false });
    expect(await repo.findUserByVerifiedEmail('a@b.com')).toBeNull();
  });

  it('повтор verified email другому пользователю бросает (partial-unique)', async () => {
    const u1 = await repo.createUser({});
    const u2 = await repo.createUser({});
    await repo.addEmail({ userId: u1.id, email: 'dup@x.com', verified: true });
    await expect(
      repo.addEmail({ userId: u2.id, email: 'dup@x.com', verified: true }),
    ).rejects.toThrow();
  });

  it('markEmailVerified меняет флаг', async () => {
    const user = await repo.createUser({});
    const email = await repo.addEmail({
      userId: user.id,
      email: 'a@b.com',
      verified: false,
    });
    expect(email.verified).toBe(false);
    await repo.markEmailVerified(email.id);

    const found = await repo.findEmail(user.id, 'a@b.com');
    expect(found?.verified).toBe(true);
    expect((await repo.findUserByVerifiedEmail('a@b.com'))?.id).toBe(user.id);
  });

  it('findEmail нормализует адрес; findEmailsForUser возвращает все', async () => {
    const user = await repo.createUser({});
    const other = await repo.createUser({});
    await repo.addEmail({ userId: user.id, email: 'a@b.com', verified: true });
    await repo.addEmail({ userId: user.id, email: 'c@d.com', verified: false });

    expect(await repo.findEmail(user.id, '  A@B.com ')).not.toBeNull();
    expect(await repo.findEmail(user.id, 'nope@x.com')).toBeNull();

    const emails = await repo.findEmailsForUser(user.id);
    expect(emails.map((e) => e.email).sort()).toEqual(['a@b.com', 'c@d.com']);
    expect(await repo.findEmailsForUser(other.id)).toEqual([]);
  });
});
