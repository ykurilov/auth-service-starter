import { describe, it, expect } from 'vitest';
import { InMemoryAuthorizationCodeStore } from '../../../src/adapters/repository/in-memory-authorization-code-store.js';
import type { AuthorizationCodeRecord } from '../../../src/domain/login/authorization-code.js';

const at = (iso: string) => new Date(iso);

function rec(over: Partial<AuthorizationCodeRecord> = {}): AuthorizationCodeRecord {
  return {
    id: over.id ?? 'id-1',
    codeHash: over.codeHash ?? 'hash',
    clientId: over.clientId ?? 'app1',
    clientType: over.clientType ?? 'internal',
    userId: over.userId ?? 'u1',
    redirectUri: over.redirectUri ?? 'https://app1/cb',
    codeChallenge: over.codeChallenge ?? 'chal',
    scope: over.scope ?? 'openid',
    nonce: over.nonce,
    auth: over.auth ?? { provider: 'email', emailVerified: false },
    expiresAt: over.expiresAt ?? at('2026-07-01T00:01:00Z'),
    consumedAt: over.consumedAt ?? null,
  };
}

describe('InMemoryAuthorizationCodeStore', () => {
  it('findActiveByHash находит непросроченный непогашенный код', async () => {
    const store = new InMemoryAuthorizationCodeStore();
    await store.save(rec());
    expect((await store.findActiveByHash('hash', at('2026-07-01T00:00:30Z')))?.id).toBe('id-1');
  });

  it('findActiveByHash игнорирует просроченный', async () => {
    const store = new InMemoryAuthorizationCodeStore();
    await store.save(rec());
    expect(await store.findActiveByHash('hash', at('2026-07-01T00:02:00Z'))).toBeNull();
  });

  it('findActiveByHash игнорирует погашенный', async () => {
    const store = new InMemoryAuthorizationCodeStore();
    await store.save(rec({ consumedAt: at('2026-07-01T00:00:10Z') }));
    expect(await store.findActiveByHash('hash', at('2026-07-01T00:00:30Z'))).toBeNull();
  });

  it('consume гасит и возвращает true, повторно — false (CAS)', async () => {
    const store = new InMemoryAuthorizationCodeStore();
    await store.save(rec());
    expect(await store.consume('id-1', at('2026-07-01T00:00:30Z'))).toBe(true);
    expect(await store.consume('id-1', at('2026-07-01T00:00:31Z'))).toBe(false);
    expect(await store.findActiveByHash('hash', at('2026-07-01T00:00:32Z'))).toBeNull();
  });

  it('consume по несуществующему id возвращает false', async () => {
    const store = new InMemoryAuthorizationCodeStore();
    expect(await store.consume('нет', at('2026-07-01T00:00:30Z'))).toBe(false);
  });

  it('findActiveByHash возвращает копию (в т.ч. вложенного auth)', async () => {
    const store = new InMemoryAuthorizationCodeStore();
    await store.save(rec({ auth: { provider: 'email', emailVerified: true } }));
    const a = await store.findActiveByHash('hash', at('2026-07-01T00:00:30Z'));
    if (a) {
      a.userId = 'MUT';
      a.auth.provider = 'HACK';
    }
    const b = await store.findActiveByHash('hash', at('2026-07-01T00:00:31Z'));
    expect(b?.userId).toBe('u1');
    expect(b?.auth.provider).toBe('email');
  });

  it('deleteExpired не трогает живой код', async () => {
    const store = new InMemoryAuthorizationCodeStore();
    await store.save(rec({ id: 'live', expiresAt: at('2026-07-01T00:01:00Z') }));
    const deleted = await store.deleteExpired(at('2026-07-01T00:00:00Z'));
    expect(deleted).toBe(0);
    expect(await store.findActiveByHash('hash', at('2026-07-01T00:00:30Z'))).not.toBeNull();
  });

  it('deleteExpired удаляет протухший код (в т.ч. непогашенный) и возвращает счётчик', async () => {
    const store = new InMemoryAuthorizationCodeStore();
    await store.save(rec({ id: 'expired', codeHash: 'hash-expired', expiresAt: at('2026-07-01T00:00:00Z') }));
    const deleted = await store.deleteExpired(at('2026-07-01T00:01:00Z'));
    expect(deleted).toBe(1);
    // Проверяем реальное удаление, а не просто маскировку через findActiveByHash:
    // повторное deleteExpired больше ничего не находит.
    expect(await store.deleteExpired(at('2026-07-01T00:01:00Z'))).toBe(0);
  });
});
