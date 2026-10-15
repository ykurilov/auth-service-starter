import { describe, it, expect, beforeEach } from 'vitest';
import { InMemorySigningKeyStore } from '../../../src/adapters/repository/in-memory-signing-key-store.js';
import type { StoredSigningKey } from '../../../src/domain/tokens/signing-key-store.js';

function makeKey(overrides: Partial<StoredSigningKey> = {}): StoredSigningKey {
  return {
    kid: `kid-${Math.random().toString(36).slice(2)}`,
    privatePem: 'storage-only-private-placeholder',
    publicPem: '-----BEGIN PUBLIC KEY-----\npub\n-----END PUBLIC KEY-----',
    alg: 'RS256',
    status: 'active',
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    retiredAt: null,
    revokedAt: null,
    ...overrides,
  };
}

describe('InMemorySigningKeyStore', () => {
  let store: InMemorySigningKeyStore;

  beforeEach(() => {
    store = new InMemorySigningKeyStore();
  });

  it('insertActive -> getActive round-trip', async () => {
    const key = makeKey();
    await store.insertActive(key);

    expect(await store.getActive()).toEqual(key);
  });

  it('getActive без ключей -> null', async () => {
    expect(await store.getActive()).toBeNull();
  });

  it('listAll возвращает все ключи копиями (мутация не протекает внутрь)', async () => {
    const key = makeKey();
    await store.insertActive(key);

    const all = await store.listAll();
    expect(all).toHaveLength(1);
    all[0]!.status = 'retired';

    expect((await store.getActive())?.status).toBe('active');
  });

  it('rotate снимает прежний active (retired + retiredAt) и делает новый active', async () => {
    const oldKey = makeKey({ kid: 'old' });
    await store.insertActive(oldKey);

    const newKey = makeKey({ kid: 'new' });
    const at = new Date('2026-02-01T00:00:00.000Z');
    await store.rotate(newKey, at);

    expect((await store.getActive())?.kid).toBe('new');

    const all = await store.listAll();
    const retired = all.find((k) => k.kid === 'old');
    expect(retired?.status).toBe('retired');
    expect(retired?.retiredAt).toEqual(at);

    const actives = all.filter((k) => k.status === 'active');
    expect(actives).toHaveLength(1);
  });

  it('ensureActive на пустом сторе создаёт active и возвращает его', async () => {
    const key = makeKey({ kid: 'seed' });
    const result = await store.ensureActive(key);

    expect(result.kid).toBe('seed');
    expect(await store.getActive()).toEqual(key);
  });

  it('ensureActive идемпотентен: повторный вызов возвращает существующий active', async () => {
    const first = await store.ensureActive(makeKey({ kid: 'first' }));
    const second = await store.ensureActive(makeKey({ kid: 'second' }));

    expect(first.kid).toBe('first');
    expect(second.kid).toBe('first');
    expect((await store.listAll()).filter((k) => k.status === 'active')).toHaveLength(1);
  });

  it('две параллельные попытки seed -> ровно один active, оба вызова дают один kid', async () => {
    const [a, b] = await Promise.all([
      store.ensureActive(makeKey({ kid: 'a' })),
      store.ensureActive(makeKey({ kid: 'b' })),
    ]);

    expect(a.kid).toBe(b.kid);

    const actives = (await store.listAll()).filter((k) => k.status === 'active');
    expect(actives).toHaveLength(1);
    expect(actives[0]!.kid).toBe(a.kid);
  });
});
