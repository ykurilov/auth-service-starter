// Браузерная часть входа для фронта (Vite и любой другой): узнать, кто вошёл,
// отправить на вход и выход. Сессия живёт в HttpOnly-cookie на сервере, фронт
// её не читает — только спрашивает /api/auth/me. Файл самодостаточный:
// копируется во фронт отдельно от серверной папки модуля.

// Совпадает с SessionUser серверной части (module/server/core/session-data.ts).
export interface SessionUser {
  id: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  roles: string[];
}

// GET показывает подтверждение; отзыв сессии выполняется защищённым POST.
export const LOGOUT_URL = '/api/auth/logout';

const ME_URL = '/api/auth/me';
const LOGIN_URL = '/api/auth/login';
// Метка «тихая проверка уже была» в адресе: так её возвращает сервер, если в
// браузере отключены cookie.
const SILENT_CHECK_MARK = 'auth_silent_checked';

// Текущая страница без метки тихой проверки — её незачем таскать дальше.
function currentPath(): string {
  const params = new URLSearchParams(location.search);
  params.delete(SILENT_CHECK_MARK);
  const query = params.toString();
  return location.pathname + (query ? `?${query}` : '');
}

// Адрес входа: сначала тихая проверка SSO, не вышло — экран входа; после входа
// вернёт на next (по умолчанию — на текущую страницу).
export function loginUrl(next: string = currentPath()): string {
  return `${LOGIN_URL}?next=${encodeURIComponent(next)}`;
}

// Уходим со страницы: промис не завершается, код после await не выполнится.
function leaveTo(url: string): Promise<never> {
  location.assign(url);
  return new Promise<never>(() => {});
}

// Кто вошёл, или null. Если не вошёл и тихой проверки SSO ещё не было, один
// раз уходит на тихий вход: вошедший в соседнее приложение Гильдии вернётся
// уже с сессией, остальные — сюда же, и тогда получат null.
// silentLogin: false — без тихого входа, сразу null.
export async function loadUser(options: { silentLogin?: boolean } = {}): Promise<SessionUser | null> {
  const res = await fetch(ME_URL, { credentials: 'same-origin', headers: { accept: 'application/json' } });
  if (res.ok) return ((await res.json()) as { user: SessionUser }).user;
  // Временный сбой сохраняет cookie: повтор запроса должен обойтись без login.
  if (res.status === 503) throw new Error('Сервис входа временно недоступен. Попробуйте ещё раз.');
  if (res.status !== 401) throw new Error(`Не удалось узнать, кто вошёл: ответ ${res.status}`);

  const body = (await res.json().catch(() => ({}))) as { silentChecked?: boolean };
  const checked = body.silentChecked === true || new URLSearchParams(location.search).has(SILENT_CHECK_MARK);
  if (options.silentLogin === false || checked) return null;
  return leaveTo(`${LOGIN_URL}?silent=1&next=${encodeURIComponent(currentPath())}`);
}

// Для страниц только для вошедших: не вошёл — уходит на вход и после него
// возвращается сюда.
export async function requireUser(): Promise<SessionUser> {
  const user = await loadUser({ silentLogin: false });
  return user ?? leaveTo(loginUrl());
}
