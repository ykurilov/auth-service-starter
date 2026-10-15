import { describe, it, expect } from 'vitest';
import { getUser, silentCheckDone } from '../../module/server/server.js';
import { seal } from '../../module/server/core/cookie-seal.js';
import { SILENT_CHECK_PARAM } from '../../module/server/cookies.js';
import { cookieNamesFor } from './helpers.js';

const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1';
const env = { AUTH_URL: 'https://auth.test', AUTH_APP_URL: 'https://app.test', AUTH_COOKIE_SECRET: SECRET };
const { session: SESSION_COOKIE, silentCheck: SILENT_CHECK_COOKIE } = cookieNamesFor(env);

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
    expect(silentCheckDone(`a=1; ${SILENT_CHECK_COOKIE}=1`, undefined, { env })).toBe(true);
  });
  it('метка в адресе возврата (cookie отключены) -> true', () => {
    expect(silentCheckDone(null, new URLSearchParams(`${SILENT_CHECK_PARAM}=1`), { env })).toBe(true);
    expect(silentCheckDone(null, { [SILENT_CHECK_PARAM]: '1' }, { env })).toBe(true);
    expect(silentCheckDone(null, { other: '1' }, { env })).toBe(false);
  });
  // Без AUTH_APP_URL суффикс неизвестен: страница не падает, а признаёт метку
  // с любым client id. Худшее — один пропущенный тихий вход, круга нет.
  it('без AUTH_APP_URL не падает и признаёт метку любого client id', () => {
    for (const cookie of ['__Host-auth_silent_checked.app.test=1', 'auth_silent_checked.nextjs-demo=1'])
      expect(silentCheckDone(cookie, undefined, { env: {} })).toBe(true);
    expect(silentCheckDone('a=1; auth_silent_checked=1', undefined, { env: {} })).toBe(false);
    expect(silentCheckDone(null, { [SILENT_CHECK_PARAM]: '1' }, { env: {} })).toBe(true);
    expect(silentCheckDone(null, undefined, { env: {} })).toBe(false);
  });
  it('нет метки -> false', () => {
    expect(silentCheckDone(null, undefined, { env })).toBe(false);
    expect(silentCheckDone('a=1', undefined, { env })).toBe(false);
  });
});
