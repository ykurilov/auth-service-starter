# Auth V3: модуль входа для приложения

Модуль выполняет вход через Auth V3 с PKCE, хранит токены в зашифрованной
HttpOnly-cookie и обновляет сессию на сервере. Браузер получает только профиль
пользователя. Нужны Node.js 20+ либо совместимая среда с Web Crypto, fetch,
Request и Response. Сам модуль не импортирует Next.js, Hono или другие пакеты.

Скопируйте `module/server` целиком в серверную папку приложения, например
`src/auth`. Для Vite скопируйте также `module/browser/auth-client.ts` во фронт.
Клиент должен быть заранее зарегистрирован в Auth V3. Callback фиксирован:
`<origin приложения>/api/auth/callback`; адрес возврата после выхода — `<origin>/`.

## Конфигурация

Задайте на сервере приложения:

```text
AUTH_URL=https://auth.example.com
AUTH_APP_URL=https://app.example.com
AUTH_COOKIE_SECRET=<случайный секрет не короче 32 символов>
```

Секрет должен совпадать у всех экземпляров одного приложения. Не включайте его
в клиентскую сборку или публичный репозиторий. У разных приложений должны быть
разные секреты. `AUTH_CLIENT_ID` необязателен: по умолчанию это hostname
`AUTH_APP_URL`. Адреса используются как origin, без подпути.

Фабрики принимают `{ env, fetch?, timeoutMs? }`. `fetch` можно внедрить для
тестов; он должен соблюдать `AbortSignal`. По умолчанию deadline обращения к
Auth V3 — 10 секунд, включая чтение token response. Он действует и для revoke.
Запросы не следуют HTTP-редиректам. Успешный token response проверяется по
типам, непустым токенам, `token_type=Bearer` и положительному целому
`expires_in` не более 30 дней. При сборке сессии проверяются claims и совпадение
`sub` обоих JWT; срок access ограничен также его `exp`, если он присутствует.
Подпись JWT повторно не проверяется: токены получены напрямую от доверенного
Auth V3, поэтому адрес сервиса должен быть HTTPS, кроме локальной разработки.

## Next.js

Для ESM-импортов `./x.js` из `.ts` добавьте в `next.config.mjs`:

```js
export default {
  webpack(config) {
    config.resolve.extensionAlias = { '.js': ['.ts', '.js'] };
    return config;
  },
};
```

`app/api/auth/[action]/route.ts`:

```ts
import { createAuthHandlers } from '@/auth';
export const { GET, POST } = createAuthHandlers({ env: process.env });
```

`middleware.ts`:

```ts
import { createAuthMiddleware } from '@/auth';
import { NextResponse, type NextRequest } from 'next/server';

const auth = createAuthMiddleware({ env: process.env, protect: ['/dashboard'] });

export function middleware(req: NextRequest) {
  return auth(req, (headers) => NextResponse.next({ request: { headers } }));
}

export const config = {
  matcher: ['/((?!api/auth/|_next/static|_next/image|favicon.ico).*)'],
};
```

Callback middleware теперь получает `Headers` текущего запроса: обновлённая
сессия уже доступна серверным компонентам через `headers()` и `cookies()`.
При очистке сессии она удалена и из текущего запроса. Остальные cookies и
заголовки сохраняются. Прежний `() => NextResponse.next()` поддерживается:
адаптер сам дописывает протокол Next.js request header overrides. Передача
`headers` явно предпочтительна, особенно если приложение меняет заголовки само.
Возвращать из callback обычный `Response(200)` в реальном Next.js нельзя —
это завершит запрос вместо продолжения.

Серверный компонент:

```tsx
import { getUser } from '@/auth';
import { headers } from 'next/headers';

export default async function Page() {
  const user = await getUser((await headers()).get('cookie'));
  return user ? <p>Привет, {user.name ?? user.id}</p>
    : <a href="/api/auth/login?next=/dashboard">Войти</a>;
}
```

`getUser()` только читает сессию: просроченный sealed-конверт или access дают
`null`. Для refresh нужен middleware либо `/api/auth/me`. Не используйте
клиентское отображение пользователя как защиту серверных данных.

## Hono + Vite

```ts
import { Hono } from 'hono';
import { createHonoAuth } from './auth/hono.js';

const app = new Hono();
const auth = createHonoAuth({ env: process.env, protect: ['/api/notes'] });
app.use(auth.guard);
app.on(['GET', 'POST'], '/api/auth/*', auth.routes);
app.get('/api/notes', async (c) => {
  const user = await auth.user(c);
  if (!user) return c.json({ error: 'unauthenticated' }, 401);
  return c.json({ owner: user.id });
});
```

`auth.user(c)` после guard возвращает результат проверки именно текущего
запроса, включая refresh или очистку. Без guard он только читает сессию.
`/api/auth/me` самостоятельно обновляет сессию и работает без внешнего guard.
Для выхода необходима регистрация POST, одного `app.get()` недостаточно.

В разработке Vite должен проксировать `/api` на Hono. `AUTH_APP_URL` — адрес,
который видит браузер, например `http://localhost:3007`. Если страницы отдаёт
Vite или CDN, серверная защита HTML на Hono к ним не применяется: защищайте
API и используйте `requireUser()` для интерфейса. Если HTML отдаёт Hono,
добавьте нужные пути страниц в `protect`.

Во фронте:

```ts
import { loadUser, requireUser, loginUrl, LOGOUT_URL } from './auth-client';

const user = await loadUser(); // публичная страница, одна тихая проверка SSO
// const user = await requireUser(); // закрытый интерфейс, при 401 переход на вход
// const user = await loadUser({ silentLogin: false }); // без автоматического SSO
```

`loadUser()`/`requireUser()` могут выбросить ошибку при сети/503. Покажите её
пользователю и предложите повтор. Ошибка 503 не запускает вход и не стирает
cookie. `loginUrl()` возвращает ссылку входа с возвратом на текущую страницу;
`LOGOUT_URL` — `/api/auth/logout`.

## Сроки и ошибки сессии

- Обновление начинается за 120 секунд до истечения access. Одновременные
  refresh внутри одной фабрики склеиваются. Между экземплярами приложения
  требуется Auth V3 с идемпотентным refresh: повтор A в grace window возвращает
  тот же B, не погашая B.
- Сеть, timeout, 429, 5xx и некорректный ответ сервиса сохраняют браузерную
  cookie. Пока access действителен, запрос проходит. После истечения access
  защищённый запрос и `/me` получают `503 temporarily_unavailable` с
  `Retry-After: 5`. Публичный обработчик проходит анонимно; старая cookie
  сохраняется в браузере для следующей попытки.
- Подтверждённый HTTP 400 с `invalid_grant` удаляет сессию. Без сессии
  защищённая навигация получает редирект на вход, запрос данных — 401.
  Обрабатывайте 401 в клиентском коде; автоматический переход зависит от
  поведения фреймворка. `/me` отвечает 401 с `silentChecked`.
- Sealed session живёт максимум 30 дней с последней выдачи/обновления.
  Сервер проверяет срок внутри аутентифицированного конверта; браузерный
  `Max-Age` не является единственной проверкой. Серверный срок refresh в Auth V3
  может завершить сессию раньше.

## Тихий вход и несколько вкладок

- `/api/auth/login?next=/x` сначала проверяет SSO с `prompt=none`, затем при
  необходимости открывает интерактивный вход.
- `silent=1` выполняет только тихую проверку и возвращает на публичную страницу.
- `silent=0` сразу открывает интерактивный вход; смену аккаунта можно выбрать
  на странице сервиса.

Каждая попытка имеет отдельную cookie `__Host-auth_flow.<random-state>`, свой
PKCE verifier и точную проверку state. Callback удаляет только совпавшую
попытку. Незнакомый state не удаляет cookies других вкладок. Flow и запасной
next внутри silent state имеют серверный TTL 10 минут. При старте допускается
до четырёх активных flow из cookie запроса; лишняя попытка получает 429 с
понятным сообщением. Завершение одной попытки освобождает место; истёкшие
очищаются при следующем входе. Полностью одновременные старты, ещё не видящие
cookies друг друга, могут временно превысить этот предел: глобального
серверного хранилища попыток модуль не использует.

Метка тихой проверки живёт 5 минут и не даёт повторять неудачный SSO по кругу.
Если cookie отключены, `silent=1` возвращает метку `auth_silent_checked` в query.
Публичная Next.js-страница обязана учитывать и cookie, и query:

```tsx
import { getUser, silentCheckDone } from '@/auth';
import { headers } from 'next/headers';
import { redirect } from 'next/navigation';

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };
export default async function Home({ searchParams }: Props) {
  const cookie = (await headers()).get('cookie');
  const user = await getUser(cookie);
  if (!user && !silentCheckDone(cookie, await searchParams))
    redirect('/api/auth/login?silent=1&next=/');
  return user ? <p>Привет, {user.name ?? user.id}</p>
    : <a href="/api/auth/login?next=/">Войти</a>;
}
```

В среде без `process.env` передайте конфигурацию третьим аргументом
`silentCheckDone(cookie, searchParams, { env })`; это нужно и для определения
локальных HTTP-имён. Возврат `next` ограничен внутренним путём до 1024 байт,
без обратных слэшей и управляющих символов. Ошибка входа показывает страницу
с ручным повтором, а не бесконечно запускает новый вход.

## Cookies и переход со старого модуля

На HTTPS используются `__Host-auth_session`, `__Host-auth_silent_checked`,
`__Host-auth_logout` и отдельные `__Host-auth_flow.<state>`. Все имеют
`Secure; HttpOnly; SameSite=Lax; Path=/` без Domain. Cookie с legacy-именами
на HTTPS не читаются, даже если корректно зашифрованы. Только для
`http://localhost` и `http://127.0.0.1` используются имена без `__Host-` и Secure.

Новый sealed-конверт — v2 со сроком жизни. Конверты v1 не принимаются:
после обновления модуля пользователь входит заново. При обновлении всех
экземпляров приложения используйте одну версию модуля; старые экземпляры
не понимают новые cookies. Примеры в репозитории должны быть синхронизированы
с модулем перед их использованием.

## Выход

Обычная ссылка `<a href="/api/auth/logout">Выйти</a>` открывает подтверждение.
GET и HEAD не отзывают сессию; HEAD получает 405. Подтверждение отправляет POST
с проверкой Origin, CSRF-cookie и запечатанного токена на 10 минут. После него
модуль ограниченно по времени отзывает refresh, очищает локальную сессию и
активные flow из запроса, затем ведёт на `/logout` Auth V3. Backend может
запросить отдельное подтверждение завершения общей SSO-сессии. Если его не
завершить, следующий тихий вход сможет снова использовать оставшуюся SSO.

Guard никогда не обновляет сессию на маршрутах модуля, поэтому не дописывает
свежую cookie поверх результата logout. Если revoke недоступен, локальный
выход всё равно завершается; удалённая сессия завершается при успешном отзыве
или по правилам Auth V3. Модуль не обеспечивает глобальную отмену уже летящих
запросов между экземплярами приложения.

## Другие серверы и проверки

`createSessionGuard()` возвращает `pass` с `user` и `setCookies` либо `deny`
с готовым `response`. Переносите результат guard и в контекст текущего запроса,
и в cookies ответа. `createAuthHandlers()` экспортирует GET и POST.
Ответы авторизации не должны кэшироваться; модуль ставит `Cache-Control: no-store`.

Проверки из корня репозитория:

```sh
npm run typecheck:module
npm run typecheck
npm test -- tests/module
```

Регрессии проверяют временные ошибки и отзыв, самостоятельный `/me`,
серверный TTL, несколько вкладок и PKCE/state, Hono, logout и Next.js.
Runtime-тест Next использует установленные зависимости `examples/nextjs-demo`:
в отдельном worktree путь можно задать через `AUTH_TEST_NEXT_DEMO`. Используются
настоящие NextRequest/NextResponse, request store, `headers()`/`cookies()` и
React SSR. Без установленного demo этот набор пропускается; остальные тесты
не требуют Next. Это не полноценный браузерный E2E и не production-проверка.
