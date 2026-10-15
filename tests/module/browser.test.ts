import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  loadUser,
  requireUser,
  loginUrl,
  LOGOUT_URL,
  type SessionUser as BrowserUser,
} from '../../module/browser/auth-client.js';
import type { SessionUser as ServerUser } from '../../module/server/core/session-data.js';

// Браузерная часть для фронта на Vite: «кто я», вход, тихий вход. Браузер
// подменяем: fetch отвечает как /api/auth/me, location записывает переходы.

// Файл для фронта копируется отдельно и описывает пользователя сам — тип
// обязан совпадать с серверным.
type Same<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
const sameUserType: Same<BrowserUser, ServerUser> = true;

const USER = { id: 'u1', email: 'user@x.com', roles: [] };

function stubBrowser(path: string, me: { status: number; body: unknown }) {
  const assign = vi.fn();
  const url = new URL(path, 'http://localhost:3007');
  vi.stubGlobal('location', { pathname: url.pathname, search: url.search, assign });
  const fetchMock = vi.fn(async () => Response.json(me.body, { status: me.status }));
  vi.stubGlobal('fetch', fetchMock);
  return { assign, fetchMock };
}
// Ушли со страницы — промис не завершается. Проверяем, что за тик он не решился.
async function stillPending(promise: Promise<unknown>): Promise<boolean> {
  const marker = Symbol();
  return (await Promise.race([promise, new Promise((r) => setTimeout(() => r(marker), 20))])) === marker;
}

afterEach(() => vi.unstubAllGlobals());

describe('loginUrl', () => {
  it('ведёт на вход с возвратом на текущую страницу', () => {
    stubBrowser('/notes?tab=2', { status: 200, body: {} });
    expect(loginUrl()).toBe('/api/auth/login?next=%2Fnotes%3Ftab%3D2');
  });

  it('принимает адрес возврата явно', () => {
    expect(loginUrl('/app')).toBe('/api/auth/login?next=%2Fapp');
  });

  it('метку тихой проверки в адрес возврата не переносит', () => {
    stubBrowser('/?auth_silent_checked=1&x=1', { status: 200, body: {} });
    expect(loginUrl()).toBe('/api/auth/login?next=%2F%3Fx%3D1');
  });

  it('выход — маршрут модуля', () => {
    expect(LOGOUT_URL).toBe('/api/auth/logout');
  });
});

describe('loadUser', () => {
  it('503 сохраняет возможность повтора и не запускает login', async () => {
    const { assign } = stubBrowser('/', { status: 503, body: { error: 'temporarily_unavailable' } });
    await expect(loadUser()).rejects.toThrow('временно недоступен');
    await expect(requireUser()).rejects.toThrow('временно недоступен');
    expect(assign).not.toHaveBeenCalled();
  });

  it('вошёл -> пользователь из /api/auth/me', async () => {
    const { fetchMock, assign } = stubBrowser('/', { status: 200, body: { user: USER } });
    expect(await loadUser()).toEqual(USER);
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/me', expect.objectContaining({ credentials: 'same-origin' }));
    expect(assign).not.toHaveBeenCalled();
  });

  it('не вошёл, тихой проверки не было -> один раз уходит на тихий вход', async () => {
    const { assign } = stubBrowser('/notes', {
      status: 401,
      body: { error: 'unauthenticated', silentChecked: false },
    });
    expect(await stillPending(loadUser())).toBe(true);
    expect(assign).toHaveBeenCalledWith('/api/auth/login?silent=1&next=%2Fnotes');
  });

  it('не вошёл, тихая проверка уже была -> null, без переходов', async () => {
    const { assign } = stubBrowser('/', { status: 401, body: { error: 'unauthenticated', silentChecked: true } });
    expect(await loadUser()).toBeNull();
    expect(assign).not.toHaveBeenCalled();
  });

  it('не вошёл, метка пришла в адресе (cookie отключены) -> null, без круга', async () => {
    const { assign } = stubBrowser('/?auth_silent_checked=1', {
      status: 401,
      body: { error: 'unauthenticated', silentChecked: false },
    });
    expect(await loadUser()).toBeNull();
    expect(assign).not.toHaveBeenCalled();
  });

  it('silentLogin: false -> null без тихого входа', async () => {
    const { assign } = stubBrowser('/', { status: 401, body: { error: 'unauthenticated', silentChecked: false } });
    expect(await loadUser({ silentLogin: false })).toBeNull();
    expect(assign).not.toHaveBeenCalled();
  });

  it('сервер ответил ошибкой -> исключение, а не «не вошёл»', async () => {
    stubBrowser('/', { status: 500, body: {} });
    await expect(loadUser()).rejects.toThrow();
  });
});

describe('requireUser', () => {
  it('вошёл -> пользователь', async () => {
    stubBrowser('/', { status: 200, body: { user: USER } });
    expect(await requireUser()).toEqual(USER);
  });

  it('не вошёл -> уходит на вход с возвратом сюда', async () => {
    const { assign } = stubBrowser('/notes', {
      status: 401,
      body: { error: 'unauthenticated', silentChecked: true },
    });
    expect(await stillPending(requireUser())).toBe(true);
    expect(assign).toHaveBeenCalledWith('/api/auth/login?next=%2Fnotes');
  });
});

void sameUserType;
