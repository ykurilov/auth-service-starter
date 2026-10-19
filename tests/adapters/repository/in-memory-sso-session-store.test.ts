import { describe, it, expect } from 'vitest';
import { InMemorySsoSessionStore } from '../../../src/adapters/repository/in-memory-sso-session-store.js';
import type { SsoSession } from '../../../src/domain/sso/sso-session.js';

function session(overrides: Partial<SsoSession> = {}): SsoSession {
  return {
    id: 's1',
    userId: 'u1',
    auth: { provider: 'google', email: 'a@b.c' },
    tokenHash: 'h1',
    chainId: 'chain-1',
    createdAt: new Date('2026-07-01T00:00:00Z'),
    lastUsedAt: new Date('2026-07-01T00:00:00Z'),
    expiresAt: new Date('2026-07-02T00:00:00Z'),
    revokedAt: null,
    ...overrides,
  };
}

describe('InMemorySsoSessionStore', () => {
  it('T12: findByLogin и revokeChain', async () => {
    const store = new InMemorySsoSessionStore();
    await store.save(session({ auth: { provider: 'email', loginId: 'l1' } }));
    await store.save(session({ id: 's2', tokenHash: 'h2', chainId: 'chain-2' }));
    expect((await store.findByLogin('l1'))?.id).toBe('s1');
    expect(await store.findByLogin('nope')).toBeNull();
    const at = new Date('2026-07-01T01:00:00Z');
    await store.revokeChain('chain-1', at);
    expect((await store.findByHash('h1'))?.revokedAt).toEqual(at);
    expect((await store.findByHash('h2'))?.revokedAt).toBeNull();
  });

  it('save + findByHash возвращает копию (мутация результата не портит стор)', async () => {
    const store = new InMemorySsoSessionStore();
    await store.save(session());
    const got = (await store.findByHash('h1'))!;
    expect(got.id).toBe('s1');
    got.userId = 'HACKED';
    got.auth.email = 'HACKED';
    const again = (await store.findByHash('h1'))!;
    expect(again.userId).toBe('u1');
    expect(again.auth.email).toBe('a@b.c');
  });

  it('touch обновляет lastUsedAt/expiresAt', async () => {
    const store = new InMemorySsoSessionStore();
    await store.save(session());
    const last = new Date('2026-07-01T12:00:00Z');
    const exp = new Date('2026-07-03T00:00:00Z');
    await store.touch('s1', last, exp);
    const got = (await store.findByHash('h1'))!;
    expect(got.lastUsedAt).toEqual(last);
    expect(got.expiresAt).toEqual(exp);
  });

  it('revoke ставит revokedAt', async () => {
    const store = new InMemorySsoSessionStore();
    await store.save(session());
    const at = new Date('2026-07-01T06:00:00Z');
    await store.revoke('s1', at);
    const got = (await store.findByHash('h1'))!;
    expect(got.revokedAt).toEqual(at);
  });

  it('неизвестный хеш -> null', async () => {
    const store = new InMemorySsoSessionStore();
    expect(await store.findByHash('nope')).toBeNull();
  });

  it('deleteExpired не трогает живую сессию', async () => {
    const store = new InMemorySsoSessionStore();
    await store.save(session({ expiresAt: new Date('2026-07-02T00:00:00Z') }));
    const deleted = await store.deleteExpired(new Date('2026-07-01T00:00:00Z'));
    expect(deleted).toBe(0);
    expect(await store.findByHash('h1')).not.toBeNull();
  });

  it('deleteExpired удаляет истёкшую сессию и возвращает счётчик', async () => {
    const store = new InMemorySsoSessionStore();
    await store.save(session({ expiresAt: new Date('2026-07-01T00:00:00Z') }));
    const deleted = await store.deleteExpired(new Date('2026-07-02T00:00:00Z'));
    expect(deleted).toBe(1);
    expect(await store.findByHash('h1')).toBeNull();
  });

  it('deleteExpired удаляет давно отозванную сессию, но не недавно отозванную', async () => {
    const store = new InMemorySsoSessionStore();
    await store.save(
      session({
        id: 'old-revoked',
        tokenHash: 'h-old',
        expiresAt: new Date('2026-08-01T00:00:00Z'),
        revokedAt: new Date('2026-06-01T00:00:00Z'),
      }),
    );
    await store.save(
      session({
        id: 'recent-revoked',
        tokenHash: 'h-recent',
        expiresAt: new Date('2026-08-01T00:00:00Z'),
        revokedAt: new Date('2026-06-30T12:00:00Z'),
      }),
    );
    const before = new Date('2026-06-30T00:00:00Z');
    const deleted = await store.deleteExpired(before);
    expect(deleted).toBe(1);
    expect(await store.findByHash('h-old')).toBeNull();
    expect(await store.findByHash('h-recent')).not.toBeNull();
  });
});
