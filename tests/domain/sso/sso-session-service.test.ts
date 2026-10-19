import { describe, it, expect } from 'vitest';
import { SsoSessionService } from '../../../src/domain/sso/sso-session-service.js';
import { InMemorySsoSessionStore, inMemorySsoStores } from '../../../src/adapters/repository/in-memory-sso-session-store.js';
import { InMemorySessionStore } from '../../../src/adapters/repository/in-memory-session-store.js';
import { InMemoryRefreshTokenStore } from '../../../src/adapters/repository/in-memory-refresh-token-store.js';
import { sha256Hex } from '../../../src/domain/shared/hash.js';
import { randomUUID } from 'node:crypto';
import type { Session } from '../../../src/domain/sessions/session.js';
import type { AuthSnapshot } from '../../../src/domain/login/authorization-code.js';
import { advanceableClock } from '../../helpers/advanceable-clock.js';

const TTL = 86400;
const auth: AuthSnapshot = { provider: 'google', email: 'a@b.c' };

function makeService() {
  const store = new InMemorySsoSessionStore();
  const sessions = new InMemorySessionStore(new InMemoryRefreshTokenStore());
  const clock = advanceableClock(new Date('2026-07-01T00:00:00Z'));
  const service = new SsoSessionService(inMemorySsoStores(store, sessions), clock, { ssoTtlSeconds: TTL });
  return { store, sessions, clock, service };
}

// Сессия приложения пользователя; ssoChainId — цепочка браузера, через которую выдана.
async function appSession(sessions: InMemorySessionStore, userId: string, ssoChainId?: string): Promise<Session> {
  const now = new Date('2026-07-01T00:00:00Z');
  const s: Session = { id: randomUUID(), userId, clientId: 'app', provider: 'email', profile: {}, scope: 'openid',
    deviceFingerprint: 'fp', ipHash: 'ip', createdAt: now, lastUsedAt: now,
    expiresAt: new Date('2026-08-01T00:00:00Z'), revokedAt: null, ...(ssoChainId ? { ssoChainId } : {}) };
  await sessions.save(s);
  return s;
}

describe('SsoSessionService', () => {
  it('start: в сторе только хеш, expiresAt = now + ttl', async () => {
    const { service, clock } = makeService();
    const now = clock.now();
    const { session, rawToken } = await service.start('u1', auth);
    expect(session.tokenHash).toBe(sha256Hex(rawToken));
    expect(session.expiresAt.getTime()).toBe(now.getTime() + TTL * 1000);
  });

  it('resolve свежей сессии возвращает её; повторный resolve после advance продлевает expiresAt', async () => {
    const { service, clock } = makeService();
    const { session, rawToken } = await service.start('u1', auth);
    const first = await service.resolve(rawToken);
    expect(first!.id).toBe(session.id);
    clock.advance(TTL - 1);
    const second = await service.resolve(rawToken);
    expect(second!.expiresAt.getTime()).toBeGreaterThan(first!.expiresAt.getTime());
  });

  it('resolve неизвестного токена -> null', async () => {
    const { service } = makeService();
    expect(await service.resolve('unknown-token')).toBeNull();
  });

  it('resolve после revoke -> null', async () => {
    const { service } = makeService();
    const { session, rawToken } = await service.start('u1', auth);
    await service.revoke(session.id);
    expect(await service.resolve(rawToken)).toBeNull();
  });

  it('resolve после истечения ttl -> null', async () => {
    const { service, clock } = makeService();
    const { rawToken } = await service.start('u1', auth);
    clock.advance(TTL + 1);
    expect(await service.resolve(rawToken)).toBeNull();
  });

  it('R19: start с прежним токеном отзывает прежнюю сессию', async () => {
    const { service, store } = makeService();
    const old = await service.start('u1', auth);
    const fresh = await service.start('u2', auth, old.rawToken);
    expect(await service.resolve(old.rawToken)).toBeNull();
    expect((await store.findByHash(sha256Hex(old.rawToken)))!.revokedAt).not.toBeNull();
    expect((await service.resolve(fresh.rawToken))!.userId).toBe('u2');
  });

  it('смена аккаунта начинает новую цепочку и закрывает прежнюю целиком', async () => {
    const { service, sessions } = makeService();
    const alice = await service.start('alice', auth);
    const aliceHere = await appSession(sessions, 'alice', alice.session.chainId);
    const bob = await service.start('bob', auth, alice.rawToken, alice.bindingToken);
    expect(bob.session.chainId).not.toBe(alice.session.chainId);
    expect(bob.bindingToken).not.toBe(alice.bindingToken);
    expect((await sessions.findById(aliceHere.id))!.revokedAt).not.toBeNull();
    // Прежняя привязка удалена: выход по ней Боба не гасит.
    await service.signOut(null, alice.bindingToken);
    expect(await service.resolve(bob.rawToken)).not.toBeNull();
  });

  it('повторный вход по прежней cookie после смены аккаунта продолжает прежнюю цепочку и не трогает новый аккаунт', async () => {
    const { service, sessions } = makeService();
    const alice = await service.start('alice', auth);
    const bob = await service.start('bob', auth, alice.rawToken);
    const bobHere = await appSession(sessions, 'bob', bob.session.chainId);
    const aliceAgain = await service.start('alice', auth, alice.rawToken);
    expect(aliceAgain.session.chainId).toBe(alice.session.chainId);
    expect((await sessions.findById(bobHere.id))!.revokedAt).toBeNull();
    expect(await service.resolve(bob.rawToken)).not.toBeNull();
  });

  it('повторный вход того же пользователя его сессии приложений в цепочке не гасит', async () => {
    const { service, sessions } = makeService();
    const first = await service.start('alice', auth);
    const aliceHere = await appSession(sessions, 'alice', first.session.chainId);
    await service.start('alice', auth, first.rawToken);
    expect((await sessions.findById(aliceHere.id))!.revokedAt).toBeNull();
  });

  it('R19: неизвестный прежний токен не мешает новой сессии', async () => {
    const { service } = makeService();
    const fresh = await service.start('u1', auth, 'garbage');
    expect(await service.resolve(fresh.rawToken)).not.toBeNull();
  });
});

describe('SsoSessionService.signOut (P3-3)', () => {
  const revoked = async (sessions: InMemorySessionStore, s: Session) => (await sessions.findById(s.id))!.revokedAt !== null;

  it('живой токен гасит цепочку браузера, но не сессии пользователя на других устройствах', async () => {
    const { service, sessions } = makeService();
    const { session, rawToken } = await service.start('u1', auth);
    const here = await appSession(sessions, 'u1', session.chainId);
    const phone = await appSession(sessions, 'u1');
    const otherBrowser = await appSession(sessions, 'u1', 'other-browser-chain');
    await service.signOut(rawToken);
    expect(await revoked(sessions, here)).toBe(true);
    expect(await revoked(sessions, phone)).toBe(false);
    expect(await revoked(sessions, otherBrowser)).toBe(false);
  });

  it('истёкший токен гасит только свою цепочку, не сессии на других устройствах', async () => {
    const { service, sessions, clock } = makeService();
    const { session, rawToken } = await service.start('u1', auth);
    const here = await appSession(sessions, 'u1', session.chainId);
    const phone = await appSession(sessions, 'u1');
    clock.advance(TTL + 1);
    await service.signOut(rawToken);
    expect(await revoked(sessions, here)).toBe(true);
    expect(await revoked(sessions, phone)).toBe(false);
  });

  it('отозванный последний токен цепочки (повтор после сбоя) доделывает отзыв цепочки, но не трогает другие устройства', async () => {
    const { service, sessions, store } = makeService();
    const { session, rawToken } = await service.start('u1', auth);
    const here = await appSession(sessions, 'u1', session.chainId);
    const phone = await appSession(sessions, 'u1');
    await store.revoke(session.id, new Date('2026-07-01T00:00:01Z'));
    await service.signOut(rawToken);
    expect(await revoked(sessions, here)).toBe(true);
    expect(await revoked(sessions, phone)).toBe(false);
  });

  it('токен, который браузер уже заменил новым входом, ничего не гасит', async () => {
    const { service, sessions } = makeService();
    const old = await service.start('u1', auth);
    const fresh = await service.start('u1', auth, old.rawToken);
    const here = await appSession(sessions, 'u1', fresh.session.chainId);
    const phone = await appSession(sessions, 'u1');
    await service.signOut(old.rawToken);
    expect(await revoked(sessions, here)).toBe(false);
    expect(await revoked(sessions, phone)).toBe(false);
    expect(await service.resolve(fresh.rawToken)).not.toBeNull();
  });
});
