import { describe, it, expect } from 'vitest';
import { InMemoryEmailSecretStore } from '../../../src/adapters/repository/in-memory-email-secret-store.js';
import type { EmailSecretRecord } from '../../../src/domain/email-secret/email-secret.js';

const at = (iso: string) => new Date(iso);

function rec(over: Partial<EmailSecretRecord> = {}): EmailSecretRecord {
  return {
    id: over.id ?? 'id-1',
    purpose: over.purpose ?? 'email-code-login',
    email: over.email ?? 'a@b.com',
    secretHash: over.secretHash ?? 'hash',
    expiresAt: over.expiresAt ?? at('2026-07-01T00:15:00Z'),
    consumedAt: over.consumedAt ?? null,
  };
}

describe('InMemoryEmailSecretStore', () => {
  it('findActive находит непросроченный непогашенный секрет', async () => {
    const store = new InMemoryEmailSecretStore();
    await store.save(rec());
    const found = await store.findActive('email-code-login', 'a@b.com', at('2026-07-01T00:10:00Z'));
    expect(found?.id).toBe('id-1');
  });

  it('findActive игнорирует просроченный', async () => {
    const store = new InMemoryEmailSecretStore();
    await store.save(rec());
    const found = await store.findActive('email-code-login', 'a@b.com', at('2026-07-01T00:20:00Z'));
    expect(found).toBeNull();
  });

  it('findActive игнорирует погашенный', async () => {
    const store = new InMemoryEmailSecretStore();
    await store.save(rec({ consumedAt: at('2026-07-01T00:05:00Z') }));
    const found = await store.findActive('email-code-login', 'a@b.com', at('2026-07-01T00:10:00Z'));
    expect(found).toBeNull();
  });

  it('findActive различает purpose и email', async () => {
    const store = new InMemoryEmailSecretStore();
    await store.save(rec());
    expect(await store.findActive('email-verify', 'a@b.com', at('2026-07-01T00:10:00Z'))).toBeNull();
    expect(await store.findActive('email-code-login', 'other@b.com', at('2026-07-01T00:10:00Z'))).toBeNull();
  });

  it('findActive возвращает самый свежий из нескольких активных', async () => {
    const store = new InMemoryEmailSecretStore();
    await store.save(rec({ id: 'old', expiresAt: at('2026-07-01T00:15:00Z') }));
    await store.save(rec({ id: 'new', expiresAt: at('2026-07-01T00:30:00Z') }));
    const found = await store.findActive('email-code-login', 'a@b.com', at('2026-07-01T00:10:00Z'));
    expect(found?.id).toBe('new');
  });

  it('consume гасит секрет и возвращает true, повторно — false (CAS)', async () => {
    const store = new InMemoryEmailSecretStore();
    await store.save(rec());
    expect(await store.consume('id-1', at('2026-07-01T00:10:00Z'))).toBe(true);
    expect(await store.consume('id-1', at('2026-07-01T00:11:00Z'))).toBe(false);
    expect(await store.findActive('email-code-login', 'a@b.com', at('2026-07-01T00:11:00Z'))).toBeNull();
  });

  it('consume по несуществующему id возвращает false', async () => {
    const store = new InMemoryEmailSecretStore();
    expect(await store.consume('нет-такого', at('2026-07-01T00:10:00Z'))).toBe(false);
  });

  it('invalidateActive гасит все активные секреты пары', async () => {
    const store = new InMemoryEmailSecretStore();
    await store.save(rec({ id: 'a' }));
    await store.save(rec({ id: 'b', expiresAt: at('2026-07-01T00:30:00Z') }));
    await store.invalidateActive('email-code-login', 'a@b.com', at('2026-07-01T00:05:00Z'));
    expect(await store.findActive('email-code-login', 'a@b.com', at('2026-07-01T00:06:00Z'))).toBeNull();
  });

  it('deleteExpired не трогает живой секрет', async () => {
    const store = new InMemoryEmailSecretStore();
    await store.save(rec({ id: 'live', expiresAt: at('2026-07-01T00:15:00Z') }));
    const deleted = await store.deleteExpired(at('2026-07-01T00:00:00Z'));
    expect(deleted).toBe(0);
    expect(
      await store.findActive('email-code-login', 'a@b.com', at('2026-07-01T00:10:00Z')),
    ).not.toBeNull();
  });

  it('deleteExpired удаляет протухший секрет (в т.ч. непогашенный) и возвращает счётчик', async () => {
    const store = new InMemoryEmailSecretStore();
    await store.save(rec({ id: 'expired', expiresAt: at('2026-07-01T00:00:00Z') }));
    const deleted = await store.deleteExpired(at('2026-07-01T00:01:00Z'));
    expect(deleted).toBe(1);
    expect(await store.deleteExpired(at('2026-07-01T00:01:00Z'))).toBe(0);
  });
});
