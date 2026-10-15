import { describe, it, expect } from 'vitest';
import { getUser, silentCheckDone } from '../../module/server/server.js';
import { seal } from '../../module/server/core/cookie-seal.js';
import { SESSION_COOKIE, SILENT_CHECK_COOKIE, SILENT_CHECK_PARAM } from '../../module/server/cookies.js';

const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1';
const env = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: 'https://app.test', AUTH_COOKIE_SECRET: SECRET };

describe('getUser', () => {
  it('валидная cookie -> user', async () => {
    const session = await seal(
      { user: { id: 'u1', roles: ['admin'] }, accessToken: 'a', refreshToken: 'r', accessTokenExpiresAt: Date.now() + 1e6 },
      SECRET,
    );
    const user = await getUser(`${SESSION_COOKIE}=${session}`, { env });
    expect(user).toEqual({ id: 'u1', roles: ['admin'] });
  });
  it('нет cookie -> null', async () => {
    expect(await getUser(null, { env })).toBeNull();
    expect(await getUser('', { env })).toBeNull();
  });
  it('битая cookie -> null', async () => {
    expect(await getUser(`${SESSION_COOKIE}=мусор`, { env })).toBeNull();
  });
});

describe('silentCheckDone', () => {
  it('есть метка тихой проверки -> true', () => {
    expect(silentCheckDone(`a=1; ${SILENT_CHECK_COOKIE}=1`)).toBe(true);
  });
  it('метка в адресе возврата (cookie отключены) -> true', () => {
    expect(silentCheckDone(null, new URLSearchParams(`${SILENT_CHECK_PARAM}=1`))).toBe(true);
    expect(silentCheckDone(null, { [SILENT_CHECK_PARAM]: '1' })).toBe(true);
    expect(silentCheckDone(null, { other: '1' })).toBe(false);
  });
  it('нет метки -> false', () => {
    expect(silentCheckDone(null)).toBe(false);
    expect(silentCheckDone('a=1')).toBe(false);
  });
});
