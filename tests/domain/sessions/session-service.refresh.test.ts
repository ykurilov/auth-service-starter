import { describe, it, expect } from 'vitest';
import { SessionService } from '../../../src/domain/sessions/session-service.js';
import { InMemorySessionStore } from '../../../src/adapters/repository/in-memory-session-store.js';
import { InMemoryRefreshTokenStore } from '../../../src/adapters/repository/in-memory-refresh-token-store.js';
import { TokenService } from '../../../src/domain/tokens/token-service.js';
import { loadSigningKey } from '../../../src/domain/tokens/signing-key.js';
import {
  InvalidRefreshTokenError,
  RefreshTokenReuseError,
} from '../../../src/domain/sessions/errors.js';
import { randomUUID } from 'node:crypto';
import { sha256Hex } from '../../../src/domain/shared/hash.js';
import { generateRefreshToken } from '../../../src/domain/sessions/refresh-token.js';
import { advanceableClock } from '../../helpers/advanceable-clock.js';

async function setup() {
  const key = await loadSigningKey({ autogenerate: true });
  const clock = advanceableClock(new Date('2026-07-01T00:00:00Z'));
  const tokens = new TokenService(key, [key], clock, {
    issuer: 'https://auth',
    accessTtlSeconds: 900,
    idTtlSeconds: 900,
  });
  const refresh = new InMemoryRefreshTokenStore();
  const sessions = new InMemorySessionStore(refresh);
  const service = new SessionService(sessions, refresh, tokens, clock, {
    refreshTtlSeconds: 2592000,
  });
  const otherService = new SessionService(sessions, refresh, tokens, clock, {
    refreshTtlSeconds: 2592000,
  });
  return { service, otherService, sessions, refresh, clock };
}

const startParams = {
  userId: 'u1',
  clientId: 'app',
  provider: 'email',
  profile: { email: 'a@b.co', emailVerified: true, name: 'Аня' },
  scope: 'openid profile email',
  device: { userAgent: 'Mozilla/5.0', ip: '1.2.3.4' },
};

describe('SessionService.refresh', () => {
  it('ротация: новый refresh отличается, старый гасится, сессия продлевается', async () => {
    const { service, sessions, clock } = await setup();
    const first = await service.start(startParams);
    clock.advance(3600);
    const second = await service.refresh(first.refreshToken, startParams.device);
    expect(second.refreshToken).not.toBe(first.refreshToken);
    expect(second.accessToken).toBeTruthy();
    const s = await sessions.findById(first.sessionId);
    expect(s!.expiresAt).toEqual(new Date('2026-07-31T01:00:00Z')); // now(+1ч) + 30д
    // старый больше не работает как «голова», но повтор безопасен (см. отдельный тест)
    expect(second.sessionId).toBe(first.sessionId);
  });

  it('неизвестный токен -> InvalidRefreshTokenError', async () => {
    const { service } = await setup();
    await expect(
      service.refresh('garbage', startParams.device),
    ).rejects.toBeInstanceOf(InvalidRefreshTokenError);
  });

  it('отозванная сессия -> InvalidRefreshTokenError', async () => {
    const { service, sessions, clock } = await setup();
    const first = await service.start(startParams);
    await sessions.revoke(first.sessionId, clock.now());
    await expect(
      service.refresh(first.refreshToken, startParams.device),
    ).rejects.toBeInstanceOf(InvalidRefreshTokenError);
  });

  it('истёкшая сессия -> InvalidRefreshTokenError', async () => {
    const { service, clock } = await setup();
    const first = await service.start(startParams);
    clock.advance(2592000 + 1);
    await expect(
      service.refresh(first.refreshToken, startParams.device),
    ).rejects.toBeInstanceOf(InvalidRefreshTokenError);
  });

  it('повтор без продвижения возвращает того же преемника, сессия жива', async () => {
    const { service, sessions } = await setup();
    const first = await service.start(startParams);
    const second = await service.refresh(first.refreshToken, startParams.device); // голова -> R2 (живая)
    const retry = await service.refresh(first.refreshToken, startParams.device); // повтор старого, преемник не погашен
    expect(retry.refreshToken).toBe(second.refreshToken);
    expect((await sessions.findById(first.sessionId))!.revokedAt).toBeNull();
  });

  it('отставание на один шаг, но старее окна -> reuse detected, сессия убита', async () => {
    const { service, sessions, clock } = await setup();
    const first = await service.start(startParams);
    await service.refresh(first.refreshToken, startParams.device); // R1 -> R2 (живая голова)
    // Украденный R1 предъявлен спустя долгое время: преемник в одном шаге,
    // но давность погашения выдаёт угон.
    clock.advance(61);
    await expect(
      service.refresh(first.refreshToken, startParams.device),
    ).rejects.toBeInstanceOf(RefreshTokenReuseError);
    expect((await sessions.findById(first.sessionId))!.revokedAt).not.toBeNull();
  });

  it('реальный обгон цепочки (старее окна) -> reuse detected, сессия убита', async () => {
    const { service, sessions, clock } = await setup();
    const first = await service.start(startParams);
    const second = await service.refresh(first.refreshToken, startParams.device); // R1 -> R2
    await service.refresh(second.refreshToken, startParams.device); // R2 -> R3 (R2 погашен)
    // R1 погашен давно (старее окна 60с) и обгон на 2 шага -> угон.
    clock.advance(61);
    await expect(
      service.refresh(first.refreshToken, startParams.device),
    ).rejects.toBeInstanceOf(RefreshTokenReuseError);
    expect((await sessions.findById(first.sessionId))!.revokedAt).not.toBeNull();
  });

  it('two independent services racing the same head return the same successor', async () => {
    const { service, otherService, sessions, refresh, clock } = await setup();
    const first = await service.start(startParams);
    const rotate = refresh.rotate.bind(refresh);
    let arrivals = 0;
    let release!: () => void;
    const barrier = new Promise<void>((resolve) => { release = resolve; });
    refresh.rotate = async (...args) => {
      if (++arrivals === 2) release();
      await barrier;
      return rotate(...args);
    };
    const [a, b] = await Promise.all([
      service.refresh(first.refreshToken, startParams.device),
      otherService.refresh(first.refreshToken, startParams.device),
    ]);
    refresh.rotate = rotate;
    expect(a.refreshToken).toBe(b.refreshToken);
    const head = await refresh.findByHash(sha256Hex(a.refreshToken));
    expect(head?.consumedAt).toBeNull();
    expect(head?.previousTokenId).toBe((await refresh.findByHash(sha256Hex(first.refreshToken)))?.id);
    // The earlier successful response can arrive late, beyond A's grace.
    clock.advance(61);
    await expect(otherService.refresh(b.refreshToken, startParams.device)).resolves.toBeTruthy();
    expect((await sessions.findById(first.sessionId))?.revokedAt).toBeNull();
  });

  it('A -> B, repeat A leaves B live; a delayed successful B works after grace', async () => {
    const { service, otherService, refresh, clock, sessions } = await setup();
    const a = await service.start(startParams);
    const b = await service.refresh(a.refreshToken, startParams.device);
    clock.advance(30);
    const retry = await otherService.refresh(a.refreshToken, startParams.device);
    expect(retry.refreshToken).toBe(b.refreshToken);
    expect((await refresh.findByHash(sha256Hex(b.refreshToken)))?.consumedAt).toBeNull();
    clock.advance(31);
    await expect(service.refresh(b.refreshToken, startParams.device)).resolves.toBeTruthy();
    expect((await sessions.findById(a.sessionId))?.revokedAt).toBeNull();
  });

  it('a retry recovers the committed successor after session touch fails', async () => {
    const { service, otherService, refresh, sessions } = await setup();
    const a = await service.start(startParams);
    const touch = sessions.touch.bind(sessions);
    sessions.touch = async () => { throw new Error('injected session write failure'); };
    await expect(service.refresh(a.refreshToken, startParams.device)).rejects.toThrow('injected');
    const parent = await refresh.findByHash(sha256Hex(a.refreshToken));
    expect(parent?.replacedById).toBeTruthy();
    const child = await refresh.findById(parent!.replacedById!);
    sessions.touch = touch;
    const retry = await otherService.refresh(a.refreshToken, startParams.device);
    expect(sha256Hex(retry.refreshToken)).toBe(child?.tokenHash);
    expect((await refresh.findById(child!.id))?.consumedAt).toBeNull();
  });

  it('legacy random head upgrades; a legacy consumed retry cannot revoke a live session in grace', async () => {
    const { service, refresh, sessions, clock } = await setup();
    const a = await service.start(startParams); // existing random-token format
    const parent = (await refresh.findByHash(sha256Hex(a.refreshToken)))!;
    const legacyRaw = generateRefreshToken();
    const legacyId = randomUUID();
    await refresh.consume(parent.id, legacyId, clock.now());
    await refresh.save({ id: legacyId, sessionId: a.sessionId, tokenHash: sha256Hex(legacyRaw),
      previousTokenId: parent.id, replacedById: null, createdAt: clock.now(), consumedAt: null });
    await expect(service.refresh(a.refreshToken, startParams.device)).rejects.toBeInstanceOf(InvalidRefreshTokenError);
    expect((await sessions.findById(a.sessionId))?.revokedAt).toBeNull();
    const upgraded = await service.refresh(legacyRaw, startParams.device);
    expect((await refresh.findByHash(sha256Hex(upgraded.refreshToken)))?.derivationVersion).toBe('hmac-sha256-v1');
    clock.advance(61);
    await expect(service.refresh(a.refreshToken, startParams.device)).rejects.toBeInstanceOf(RefreshTokenReuseError);
  });

  it('после reuse даже валидный последний токен не работает (сессия убита)', async () => {
    const { service, clock } = await setup();
    const first = await service.start(startParams);
    const second = await service.refresh(first.refreshToken, startParams.device);
    const third = await service.refresh(second.refreshToken, startParams.device);
    clock.advance(61); // старее окна -> предъявление R1 будет угоном
    await service.refresh(first.refreshToken, startParams.device).catch(() => {}); // reuse -> убивает сессию
    await expect(
      service.refresh(third.refreshToken, startParams.device),
    ).rejects.toBeInstanceOf(InvalidRefreshTokenError);
  });

  it('три параллельных refresh одной головы: один прямой успех, два ретрая догоняют живую голову, сессия жива', async () => {
    const { service, sessions } = await setup();
    const first = await service.start(startParams);

    // Первый refresh продвигает R1 -> R2 (голова R2 жива).
    const [r1, r2, r3] = await Promise.all([0, 1, 2].map(() =>
      service.refresh(first.refreshToken, startParams.device)));
    expect(r1!.refreshToken).toBe(r2!.refreshToken);
    expect(r2!.refreshToken).toBe(r3!.refreshToken);

    for (const r of [r1, r2, r3]) expect(r!.refreshToken).toBeTruthy();
    // Сессия жива, ни один шаг не принят за угон.
    expect((await sessions.findById(first.sessionId))!.revokedAt).toBeNull();
    // Последняя выданная голова по-прежнему валидна.
    const next = await service.refresh(r3!.refreshToken, startParams.device);
    expect(next.refreshToken).toBeTruthy();
  });

  it('обгон на 2 шага в пределах окна 60с -> легитимная гонка, сессия жива', async () => {
    const { service, sessions } = await setup();
    const first = await service.start(startParams);
    const second = await service.refresh(first.refreshToken, startParams.device); // R1 -> R2
    const third = await service.refresh(second.refreshToken, startParams.device); // R2 -> R3
    // R1 предъявлен, погашен только что (в пределах окна), обгон на 2 шага.
    const late = await service.refresh(first.refreshToken, startParams.device);
    expect(late.refreshToken).toBe(third.refreshToken);
    expect((await sessions.findById(first.sessionId))!.revokedAt).toBeNull();
  });

  it('глубина цепочки ограничена: предъявление очень старого корня -> reuse detected', async () => {
    const { service, sessions, clock } = await setup();
    const first = await service.start(startParams);
    let head = first.refreshToken;
    // Прогоняем цепочку глубже лимита (32) — с продвижением часов, чтобы корень
    // оказался старее окна.
    for (let i = 0; i < 40; i++) {
      const r = await service.refresh(head, startParams.device);
      head = r.refreshToken;
    }
    clock.advance(61);
    await expect(
      service.refresh(first.refreshToken, startParams.device),
    ).rejects.toBeInstanceOf(RefreshTokenReuseError);
    expect((await sessions.findById(first.sessionId))!.revokedAt).not.toBeNull();
  });

  it('revokeByRefreshToken гасит сессию по сырому refresh-токену', async () => {
    const { service } = await setup();
    const issued = await service.start(startParams);
    await service.revokeByRefreshToken(issued.refreshToken);
    await expect(
      service.refresh(issued.refreshToken, startParams.device),
    ).rejects.toBeInstanceOf(InvalidRefreshTokenError);
  });

  it('revokeByRefreshToken молчит на неизвестный токен', async () => {
    const { service } = await setup();
    await expect(service.revokeByRefreshToken('nope')).resolves.toBeUndefined();
  });

  it('revokeByRefreshToken по историческому токену цепочки тоже гасит сессию', async () => {
    const { service } = await setup();
    const first = await service.start(startParams);
    const second = await service.refresh(first.refreshToken, startParams.device); // first погашен ротацией
    await service.revokeByRefreshToken(first.refreshToken);
    await expect(
      service.refresh(second.refreshToken, startParams.device),
    ).rejects.toBeInstanceOf(InvalidRefreshTokenError);
  });
});
