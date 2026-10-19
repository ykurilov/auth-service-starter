import { describe, it, expect } from 'vitest';
import { InMemorySessionStore } from '../../../src/adapters/repository/in-memory-session-store.js';
import { InMemoryRefreshTokenStore } from '../../../src/adapters/repository/in-memory-refresh-token-store.js';
import { InMemorySsoSessionStore, inMemorySsoStores } from '../../../src/adapters/repository/in-memory-sso-session-store.js';
import type { SsoSession } from '../../../src/domain/sso/sso-session.js';
import { bindingContract } from './sso-binding-contract.js';

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
  bindingContract(() => new InMemorySsoSessionStore());

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

describe('R5: lockChain без БД — очередь по цепочке до конца транзакции', () => {
  const tick = () => new Promise((r) => setTimeout(r, 5));

  function stores() {
    const sso = new InMemorySsoSessionStore();
    return inMemorySsoStores(sso, new InMemorySessionStore(new InMemoryRefreshTokenStore()));
  }

  it('транзакции одной цепочки идут по очереди, разных цепочек — параллельно', async () => {
    const s = stores();
    const events: string[] = [];
    const tx = (name: string, chainId: string) =>
      s.atomically(async ({ sso }) => {
        await sso.lockChain(chainId);
        events.push(`${name}:start`);
        await tick();
        events.push(`${name}:end`);
      });
    await Promise.all([tx('a', 'c1'), tx('b', 'c1'), tx('x', 'c2')]);
    expect(events.indexOf('b:start')).toBeGreaterThan(events.indexOf('a:end'));
    expect(events.indexOf('x:start')).toBeLessThan(events.indexOf('a:end'));
  });

  it('повторная блокировка той же цепочки в транзакции не ждёт саму себя; сбой снимает блокировку', async () => {
    const s = stores();
    await s.atomically(async ({ sso }) => {
      await sso.lockChain('c1');
      await sso.lockChain('c1');
    });
    await expect(
      s.atomically(async ({ sso }) => {
        await sso.lockChain('c1');
        throw new Error('сбой');
      }),
    ).rejects.toThrow('сбой');
    await s.atomically(async ({ sso }) => sso.lockChain('c1'));
  });

  it('вне транзакции lockChain дожидается держателя и сразу отпускает', async () => {
    const s = stores();
    const events: string[] = [];
    const holder = s.atomically(async ({ sso }) => {
      await sso.lockChain('c1');
      await tick();
      events.push('holder:end');
    });
    await Promise.resolve();
    await s.sso.lockChain('c1');
    events.push('outside');
    await holder;
    expect(events).toEqual(['holder:end', 'outside']);
    await s.atomically(async ({ sso }) => sso.lockChain('c1'));
  });
});
