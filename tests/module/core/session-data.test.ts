import { describe, it, expect } from 'vitest';
import { buildSessionData } from '../../../module/server/core/session-data.js';

function fakeJwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(unescape(encodeURIComponent(JSON.stringify(o))))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  return `${b64({ alg: 'RS256' })}.${b64(payload)}.sig`;
}

describe('buildSessionData', () => {
  it('собирает user из id_token (email/name) и access_token (roles)', () => {
    const idToken = fakeJwt({ sub: 'u1', email: 'a@b.co', email_verified: true, name: 'Аня' });
    const accessToken = fakeJwt({ sub: 'u1', roles: ['admin'], exp: new Date('2026-07-02T00:15:00Z').getTime() / 1000 });
    const data = buildSessionData({
      accessToken,
      idToken,
      refreshToken: 'r1',
      expiresIn: 900,
      now: new Date('2026-07-02T00:00:00Z'),
    });
    expect(data).toEqual({
      user: { id: 'u1', email: 'a@b.co', emailVerified: true, name: 'Аня', roles: ['admin'] },
      accessToken,
      refreshToken: 'r1',
      accessTokenExpiresAt: new Date('2026-07-02T00:15:00Z').getTime(),
    });
  });

  it('roles по умолчанию — пустой массив; отсутствующие поля профиля опущены', () => {
    const idToken = fakeJwt({ sub: 'u1' });
    const accessToken = fakeJwt({ sub: 'u1' });
    const data = buildSessionData({
      accessToken,
      idToken,
      refreshToken: 'r1',
      expiresIn: 900,
      now: new Date('2026-07-02T00:00:00Z'),
    });
    expect(data).not.toBeNull();
    expect(data!.user).toEqual({ id: 'u1', roles: [] });
  });

  it('exp access ограничивает expires_in; истёкший или чужой sub не принимается', () => {
    const now = new Date('2026-07-02T00:00:00Z');
    const exp = now.getTime() / 1000 + 30;
    const base = { idToken: fakeJwt({ sub: 'u1' }), refreshToken: 'r1', expiresIn: 900, now };
    expect(buildSessionData({ ...base, accessToken: fakeJwt({ sub: 'u1', exp }) })?.accessTokenExpiresAt).toBe(exp * 1000);
    expect(buildSessionData({ ...base, accessToken: fakeJwt({ sub: 'u1', exp: exp - 31 }) })).toBeNull();
    expect(buildSessionData({ ...base, accessToken: fakeJwt({ sub: 'other' }) })).toBeNull();
  });

  it('битый id_token -> null (сессию не собрать)', () => {
    expect(
      buildSessionData({
        accessToken: fakeJwt({ sub: 'u1' }),
        idToken: 'битый',
        refreshToken: 'r1',
        expiresIn: 900,
        now: new Date(),
      }),
    ).toBeNull();
  });
});
