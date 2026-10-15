import { describe, it, expect } from 'vitest';
import { InMemoryRefreshTokenStore } from '../../../src/adapters/repository/in-memory-refresh-token-store.js';
import type { RefreshTokenRecord } from '../../../src/domain/sessions/refresh-token.js';

function rec(overrides: Partial<RefreshTokenRecord> = {}): RefreshTokenRecord {
  return {
    id: 'r1', sessionId: 's1', tokenHash: 'h1',
    previousTokenId: null, replacedById: null,
    createdAt: new Date('2026-07-01T00:00:00Z'), consumedAt: null, ...overrides,
  };
}

describe('InMemoryRefreshTokenStore', () => {
  it('save + findByHash + findById возвращают копии', async () => {
    const store = new InMemoryRefreshTokenStore();
    await store.save(rec());
    const byHash = await store.findByHash('h1');
    const byId = await store.findById('r1');
    expect(byHash!.id).toBe('r1');
    expect(byId!.tokenHash).toBe('h1');
    expect(byHash).not.toBe(byId);
  });

  it('findByHash/findById -> null для неизвестных', async () => {
    const store = new InMemoryRefreshTokenStore();
    expect(await store.findByHash('nope')).toBeNull();
    expect(await store.findById('nope')).toBeNull();
  });

  it('consume гасит один раз (CAS), проставляет replacedById и consumedAt', async () => {
    const store = new InMemoryRefreshTokenStore();
    await store.save(rec());
    const at = new Date('2026-07-02T00:00:00Z');
    expect(await store.consume('r1', 'r2', at)).toBe(true);
    expect(await store.consume('r1', 'r3', at)).toBe(false); // уже погашен
    const got = await store.findById('r1');
    expect(got!.replacedById).toBe('r2');
    expect(got!.consumedAt).toEqual(at);
  });

  it('consume неизвестного -> false', async () => {
    const store = new InMemoryRefreshTokenStore();
    expect(await store.consume('nope', 'x', new Date())).toBe(false);
  });
});
