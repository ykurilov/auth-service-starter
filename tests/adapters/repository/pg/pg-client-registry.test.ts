import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMemDb } from '../../../helpers/pg-mem-db.js';
import { runMigrations } from '../../../../src/adapters/db/migrate.js';
import type { Db } from '../../../../src/adapters/db/pool.js';
import type { Client } from '../../../../src/domain/clients/client.js';
import { PgClientRegistry } from '../../../../src/adapters/repository/pg/pg-client-registry.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../migrations',
);

function makeClient(overrides: Partial<Client> = {}): Client {
  return {
    id: 'app-1',
    type: 'internal',
    redirectUris: ['https://app.example/cb', 'https://app.example/cb2'],
    allowedProviders: ['email', 'google'],
    postLogoutRedirectUris: ['https://app.example/logout'],
    ...overrides,
  };
}

describe('PgClientRegistry на pg-mem', () => {
  let db: Db;
  let registry: PgClientRegistry;

  beforeEach(async () => {
    db = createMemDb();
    await runMigrations(db, migrationsDir);
    registry = new PgClientRegistry(db);
  });

  afterEach(async () => {
    await db.close();
  });

  it('create -> findClient, массивы читаются как массивы', async () => {
    const client = makeClient();
    await registry.create(client);

    const found = await registry.findClient('app-1');
    expect(found).toEqual({ ...client, registrationId: expect.any(String) });
    expect(Array.isArray(found?.redirectUris)).toBe(true);
    expect(found?.allowedProviders).toEqual(['email', 'google']);
    expect(found?.postLogoutRedirectUris).toEqual(['https://app.example/logout']);
  });

  it('findClient неизвестного -> null', async () => {
    expect(await registry.findClient('nope')).toBeNull();
  });

  it('postLogoutRedirectUris может отсутствовать', async () => {
    await registry.create(makeClient({ id: 'no-logout', postLogoutRedirectUris: undefined }));
    const found = await registry.findClient('no-logout');
    expect(found?.postLogoutRedirectUris).toBeUndefined();
  });

  it('upsert обновляет существующего', async () => {
    await registry.create(makeClient());
    await registry.upsert(
      makeClient({ type: 'external', redirectUris: ['https://new/cb'] }),
    );
    const found = await registry.findClient('app-1');
    expect(found?.type).toBe('external');
    expect(found?.redirectUris).toEqual(['https://new/cb']);
  });

  it('upsert создаёт нового, если его нет', async () => {
    await registry.upsert(makeClient({ id: 'fresh' }));
    expect(await registry.findClient('fresh')).not.toBeNull();
  });

  it('list возвращает всех', async () => {
    await registry.create(makeClient({ id: 'a' }));
    await registry.create(makeClient({ id: 'b' }));
    const all = await registry.list();
    expect(all.map((c) => c.id).sort()).toEqual(['a', 'b']);
  });

  it('update меняет отдельное поле', async () => {
    await registry.create(makeClient());
    await registry.update('app-1', { allowedProviders: ['vk'] });
    const found = await registry.findClient('app-1');
    expect(found?.allowedProviders).toEqual(['vk']);
    // остальные поля не тронуты
    expect(found?.type).toBe('internal');
    expect(found?.redirectUris).toEqual(['https://app.example/cb', 'https://app.example/cb2']);
  });

  it('delete убирает клиента', async () => {
    await registry.create(makeClient());
    await registry.delete('app-1');
    expect(await registry.findClient('app-1')).toBeNull();
  });
});
