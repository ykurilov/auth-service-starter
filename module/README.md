# Auth V3: модуль входа для приложения

Модуль выполняет вход через Auth V3 с PKCE, хранит токены в зашифрованной
HttpOnly-cookie и обновляет сессию на сервере. Браузер получает только профиль
пользователя. Нужны Node.js 20+ либо совместимая среда с Web Crypto, fetch,
Request и Response. Сам модуль не импортирует Next.js, Hono или другие пакеты.

Скопируйте `module/server` целиком в серверную папку приложения. В скелете
`create-next-app` это `auth/` в корне проекта (импорт `@/auth`), а при
`--src-dir` — `src/auth`. Для Vite скопируйте также
`module/browser/auth-client.ts` во фронт. Внутренние импорты модуля записаны
без расширений (`./handlers`), поэтому его без настроек собирают Turbopack,
webpack, Vite и `tsx`. Для своей проверки типов нужен
`"moduleResolution": "bundler"`, как в скелетах Next.js и Vite.
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
`AUTH_APP_URL`. Адреса используются как origin, без подпути. От client id
зависят имена cookie (см. «Cookies»): приложениям на одном hostname с разными
портами задайте разные `AUTH_CLIENT_ID`.

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

Инструкция рассчитана на Next.js 16 со скелетом `npx create-next-app@latest`:
Turbopack, `next.config.ts` с `cacheComponents: true`. В `next.config.ts`
для модуля ничего добавлять не нужно, флаг `--webpack` тоже не нужен.

Фабрики проверяют переменные `AUTH_*` сразу при создании. Создавайте их при
первом запросе, а не при загрузке файла: `next build` загружает маршруты, и
сборка без `AUTH_*` (Docker, CI без секретов) иначе упадёт. Локально задайте
их в `.env.local`, Next.js загрузит его сам.

`app/api/auth/[action]/route.ts`:

```ts
import { createAuthHandlers } from '@/auth';

let handlers: ReturnType<typeof createAuthHandlers> | undefined;
const auth = () => (handlers ??= createAuthHandlers({ env: process.env }));

export const GET = (request: Request) => auth().GET(request);
export const POST = (request: Request) => auth().POST(request);
```

`proxy.ts` в корне проекта (при `--src-dir` — в `src/`):

```ts
import { createAuthMiddleware } from '@/auth';
import { NextResponse, type NextRequest } from 'next/server';

let auth: ReturnType<typeof createAuthMiddleware> | undefined;

export function proxy(req: NextRequest) {
  auth ??= createAuthMiddleware({ env: process.env, protect: ['/dashboard'] });
  return auth(req, (headers) => NextResponse.next({ request: { headers } }));
}

export const config = {
  matcher: ['/((?!api/auth/|_next/static|_next/image|favicon.ico).*)'],
};
```

В Next.js 16 файл `middleware.ts` переименован в `proxy.ts`. Proxy всегда
работает в Node.js, в одном процессе с route handlers, и опцию `runtime` не
принимает. Поэтому выход и новый вход гасят refresh, который proxy начал
раньше (см. «Сроки и ошибки сессии»). В Next.js 15.5 тот же код лежит в
`middleware.ts`: функция называется `middleware`, а в `config` нужно добавить
`runtime: 'nodejs'`. На Edge runtime middleware живёт в отдельной песочнице и
этой защиты не получает.

Callback proxy получает `Headers` текущего запроса: обновлённая
сессия уже доступна серверным компонентам через `headers()` и `cookies()`.
При очистке сессии она удалена и из текущего запроса. Если на публичной
странице refresh временно не удался, cookie сессии в запросе остаётся, а
запрос получает метку тихой проверки: `getUser()` вернёт `null`, а
`silentCheckDone()` — `true`, и страница покажет «Войти», не уводя на
`login?silent=1`. В браузер метка не уходит, следующий запрос повторит refresh. Остальные cookies и
заголовки сохраняются. Прежний `() => NextResponse.next()` поддерживается:
адаптер сам дописывает протокол Next.js request header overrides. Передача
`headers` явно предпочтительна, особенно если приложение меняет заголовки само.
Возвращать из callback обычный `Response(200)` в реальном Next.js нельзя —
это завершит запрос вместо продолжения.

Серверный компонент. С `cacheComponents` данные запроса (`headers()`,
`cookies()`, `searchParams`) можно читать только внутри `<Suspense>`: без него
`next build` падает с ошибкой «Uncached data was accessed outside of
`<Suspense>`». Остальная страница собирается заранее, а часть с пользователем
приходит при запросе:

```tsx
import { Suspense } from 'react';
import { getUser } from '@/auth';
import { headers } from 'next/headers';

export default function Page() {
  return (
    <Suspense fallback={<p>Проверяем вход…</p>}>
      <Greeting />
    </Suspense>
  );
}

async function Greeting() {
  const user = await getUser((await headers()).get('cookie'));
  if (user) return <p>Привет, {user.name ?? user.id}</p>;
  // eslint-disable-next-line @next/next/no-html-link-for-pages
  return <a href="/api/auth/login?next=/dashboard">Войти</a>;
}
```

`user.name` есть, только если он заполнен в профиле. При входе по коду из
письма имени обычно нет: показывайте `user.email ?? user.id`.

Закрытая страница `app/dashboard/page.tsx`. Путь `/dashboard` указан в
`protect` у proxy, поэтому без входа сюда не попасть: proxy сам уведёт на
вход и вернёт обратно.

```tsx
import { Suspense } from 'react';
import { getUser } from '@/auth';
import { headers } from 'next/headers';

export default function Dashboard() {
  return (
    <main>
      <h1>Личный кабинет</h1>
      <Suspense fallback={<p>Загружаем профиль…</p>}>
        <Profile />
      </Suspense>
      {/* eslint-disable-next-line @next/next/no-html-link-for-pages */}
      <a href="/api/auth/logout">Выйти</a>
    </main>
  );
}

async function Profile() {
  const user = await getUser((await headers()).get('cookie'));
  return <p>Вы вошли как {user?.email ?? user?.id}</p>;
}
```

Ссылки на `/api/auth/login` и `/api/auth/logout` — обычные `<a>`, а не
`<Link>`: вход и выход уходят на сервис входа, нужна полная навигация
браузера. Правило `@next/next/no-html-link-for-pages` из скелета
`create-next-app` ругается на такие ссылки в `npm run lint`, поэтому в
примерах рядом стоит `eslint-disable-next-line`. Сборку это правило не
ломает.

`getUser()` только читает сессию: просроченный sealed-конверт или access дают
`null`. Для refresh нужен proxy либо `/api/auth/me`. Не используйте
клиентское отображение пользователя как защиту серверных данных.

## Hono + Vite

Проект можно создать так: `npm create vite@latest my-app -- --template vanilla-ts`,
затем `npm install hono @hono/node-server` и `npm install -D tsx @types/node`.
Модуль скопируйте в `server/auth`, клиент — в `src/auth-client.ts`. Сервер
лежит в `server/index.ts` и запускается через `tsx`: `npx tsx watch server/index.ts`
в разработке и `npx tsx server/index.ts` в боевом режиме. Переменные `AUTH_*`
положите в `.env` (в `.gitignore`) и загрузите первой строкой сервера:
`process.loadEnvFile('.env')` (Node.js 20.12+). Готовый пример —
`examples/hono-vite-demo`.

```ts
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createHonoAuth } from './auth/hono';

const app = new Hono();
const auth = createHonoAuth({ env: process.env, protect: ['/api/notes'] });
app.use(auth.guard);
app.on(['GET', 'POST'], '/api/auth/*', auth.routes);
app.get('/api/notes', async (c) => {
  const user = await auth.user(c);
  if (!user) return c.json({ error: 'unauthenticated' }, 401);
  return c.json({ owner: user.id });
});

serve({ fetch: app.fetch, port: 3008 });
```

Без сессии guard отвечает на защищённый путь по типу запроса. `fetch()` из
браузера и запрос с `Accept: application/json` получают `401`. Переход по
ссылке получает редирект на вход. Запрос без `Sec-Fetch-Mode` и с
`Accept: */*`, как у `curl` по умолчанию, тоже считается переходом и получает
`302`: проверяйте API командой `curl -H 'Accept: application/json'`.

`auth.user(c)` после guard возвращает результат проверки именно текущего
запроса, включая refresh или очистку. Без guard он только читает сессию.
`/api/auth/me` самостоятельно обновляет сессию и работает без внешнего guard.
Для выхода необходима регистрация POST, одного `app.get()` недостаточно.

В разработке Vite должен проксировать `/api` на Hono: в `vite.config.ts`
`server: { proxy: { '/api': 'http://localhost:3008' } }`. `AUTH_APP_URL` — адрес,
который видит браузер, например `http://localhost:5173` у Vite. Если страницы отдаёт
Vite или CDN, серверная защита HTML на Hono к ним не применяется: защищайте
API и используйте `requireUser()` для интерфейса. Если HTML отдаёт Hono,
добавьте нужные пути страниц в `protect`.

В боевом режиме собранные страницы (`npm run build` кладёт их в `dist/`)
обычно отдаёт сам Hono, тогда Vite не нужен. Добавьте в `server/index.ts`
после API-маршрутов, перед `serve(...)`:

```ts
import { serveStatic } from '@hono/node-server/serve-static';

if (process.env.NODE_ENV === 'production') {
  app.use('*', serveStatic({ root: './dist' }));
}
```

`serveStatic` отдаёт файлы как есть: `/` — это `dist/index.html`, а вторая
страница лежит там, куда её положил Vite, например `/cabinet.html`. Такие
страницы добавьте в `protect` (`protect: ['/api/notes', '/cabinet.html']`),
и guard без входа уведёт на вход. `AUTH_APP_URL` в боевом режиме — адрес
Hono, а не Vite. Запуск: `npm run build`, затем
`NODE_ENV=production npx tsx server/index.ts`.

Во фронте:

```ts
import { loadUser, requireUser, loginUrl, LOGOUT_URL } from './auth-client';

const user = await loadUser(); // публичная страница, одна тихая проверка SSO
// const user = await requireUser(); // закрытый интерфейс, при 401 переход на вход
// const user = await loadUser({ silentLogin: false }); // без автоматического SSO
```

`loadUser()`/`requireUser()` могут выбросить ошибку при сети/503. Покажите её
пользователю и предложите повтор. Ошибка 503 не запускает вход и не стирает
cookie. После сбоя сервиса входа модуль 15 секунд не обращается к нему (см.
«Сроки и ошибки сессии»), поэтому «Повторить» в эти секунды снова покажет
ошибку, даже если сервис уже поднялся. Напишите это рядом с кнопкой, например
«Попробуйте через 15–20 секунд», или повторяйте сами через 20 секунд. `loginUrl()` возвращает ссылку входа с возвратом на текущую страницу;
`LOGOUT_URL` — `/api/auth/logout`.

## Сроки и ошибки сессии

- Обновление начинается за 120 секунд до истечения access. Одновременные
  refresh внутри одной фабрики склеиваются. Между экземплярами приложения
  требуется Auth V3 с идемпотентным refresh: повтор A в grace window возвращает
  тот же B, не погашая B.
- Выход и успешный callback закрывают прежнюю сессию: её refresh-токен
  отзывается в Auth V3 и помечается в памяти процесса на 10 минут. Летящий
  или запоздавший refresh этого токена не выдаёт `Set-Cookie`: не возвращает
  сессию после выхода и не затирает сессию нового входа. Пометка одна на
  процесс для каждого client id: её видят все фабрики модуля — обработчики,
  guard, Hono и proxy Next.js (или middleware в Node runtime). Настраивать ничего не нужно.
- Ограничение: пометка не выходит за пределы процесса. Если у приложения
  несколько экземпляров или middleware Next.js 15 работает на Edge runtime,
  refresh, начатый до выхода в другом процессе или песочнице, ещё может
  вернуть cookie прежней сессии. Её refresh-токен уже отозван, поэтому такая
  сессия живёт не дольше срока access (обычно 15 минут) и не обновляется.
  Глобальной отмены запросов между процессами модуль не делает.
- Сеть, timeout, 429, 5xx и некорректный ответ сервиса сохраняют браузерную
  cookie. Пока access действителен, запрос проходит. После истечения access
  защищённый запрос и `/me` получают `503 temporarily_unavailable` с
  `Retry-After: 5`. Переход по странице вместо JSON получает HTML-страницу с
  пояснением, которая сама обновляется через 5 секунд; запросы API (fetch)
  по-прежнему получают JSON. Публичный обработчик проходит анонимно; старая
  cookie сохраняется в браузере для следующей попытки.
- Если сервис недоступен (нет сети, истёк deadline, 5xx), фабрика 15 секунд
  не обращается к нему за refresh ни для одной сессии: запросы сразу идут по
  правилу выше и не ждут deadline по очереди. 429, прочие 4xx и некорректный
  ответ касаются только своей сессии и паузы не ставят.
- Подтверждённый HTTP 400 с `invalid_grant` завершает сессию: запрос идёт без
  пользователя. Cookie при этом не стирается: запрос мог уйти со старой cookie
  до нового входа, и `Max-Age=0` в его ответе стёр бы новую сессию. Мёртвую
  cookie перезапишет следующий вход; фабрика помнит отказ 10 минут и не
  спрашивает сервис повторно. Без сессии защищённая навигация получает
  редирект на вход, запрос данных — 401.
  Обрабатывайте 401 в клиентском коде; автоматический переход зависит от
  поведения фреймворка. `/me` отвечает 401 с `silentChecked`.
- Sealed session живёт максимум 30 дней с последней выдачи/обновления.
  Сервер проверяет срок внутри аутентифицированного конверта; браузерный
  `Max-Age` не является единственной проверкой. Серверный срок refresh в Auth V3
  может завершить сессию раньше.

## Тихий вход и несколько вкладок

- `/api/auth/login?next=/x` сначала проверяет SSO с `prompt=none`, затем при
  необходимости открывает интерактивный вход. Метка тихой проверки этот шаг
  не отменяет: пользователь мог войти в соседнее приложение, и тогда вход
  в internal-приложение пройдёт без экрана входа и согласия. External-приложение
  получает вход только после экрана согласия.
- `silent=1` выполняет только тихую проверку и возвращает на публичную страницу.
- `silent=0` сразу открывает интерактивный вход; смену аккаунта можно выбрать
  на странице сервиса.

Каждая попытка имеет отдельную cookie `__Host-auth_flow.<client-id>.<random-state>`,
свой PKCE verifier и точную проверку state. Callback удаляет только совпавшую
попытку. Незнакомый state не удаляет cookies других вкладок. `next` едет
запечатанным в самом state, а cookie попытки хранит только его хеш, поэтому
она весит около 400 байт при любом `next`. Попытка живёт час: код из письма
действует 15 минут, и каждая из трёх переотправок продлевает его ещё на 15.
Активных попыток в браузере не больше четырёх: новая вытесняет самую старую,
так что брошенные вкладки не блокируют вход, а заголовок `Cookie` не растёт.
Истёкшие очищаются при любом следующем входе. Полностью одновременные старты,
ещё не видящие cookies друг друга, могут временно превысить этот предел:
глобального серверного хранилища попыток модуль не использует.

Метка тихой проверки живёт 5 минут и не даёт повторять неудачный SSO по кругу.
Если cookie отключены, `silent=1` возвращает метку `auth_silent_checked` в query.
Публичная Next.js-страница обязана учитывать и cookie, и query:

```tsx
import { Suspense } from 'react';
import { getUser, silentCheckDone } from '@/auth';
import { headers } from 'next/headers';
import { redirect } from 'next/navigation';

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default function Home({ searchParams }: Props) {
  return (
    <Suspense fallback={<p>Проверяем вход…</p>}>
      <Greeting searchParams={searchParams} />
    </Suspense>
  );
}

async function Greeting({ searchParams }: Props) {
  const cookie = (await headers()).get('cookie');
  const user = await getUser(cookie);
  if (!user && !silentCheckDone(cookie, await searchParams))
    redirect('/api/auth/login?silent=1&next=/');
  if (user) return <p>Привет, {user.name ?? user.id}</p>;
  // eslint-disable-next-line @next/next/no-html-link-for-pages
  return <a href="/api/auth/login?next=/">Войти</a>;
}
```

В среде без `process.env` передайте конфигурацию третьим аргументом
`silentCheckDone(cookie, searchParams, { env })`; это нужно и для определения
имён cookie. Если `AUTH_APP_URL` всё же не найден, функция не роняет страницу,
а признаёт метку тихой проверки с любым client id. Ошибиться так можно только
в сторону «проверка уже была»: страница покажет «Войти» вместо одного тихого
входа, круга редиректов не будет. Обработчики входа без `AUTH_APP_URL` не
создаются, поэтому ошибка конфигурации видна сразу. Возврат
`next` — только внутренний путь без обратных слэшей и управляющих символов.
Модуль нормализует его и кодирует не-ASCII: `next=/кабинет` вернёт на
`/%D0%BA%D0%B0...`, браузер покажет это как `/кабинет`. `next` длиннее 2048
байт после кодирования сокращается до пути страницы без query, а если длинен
и путь — до `/`. Ошибка входа
показывает страницу с ручным повтором, а не бесконечно запускает новый вход.
Это относится и к сбою собственного входа при живой прежней сессии: модуль
не возвращает молча на старую сессию. Чужой или повторный callback у
вошедшего пользователя по-прежнему ведёт на `/`.

## Cookies и переход со старого модуля

Имена cookie несут суффикс client id. На HTTPS это
`__Host-auth_session.<client-id>`, `__Host-auth_silent_checked.<client-id>`,
`__Host-auth_logout.<client-id>` и отдельные
`__Host-auth_flow.<client-id>.<state>`. Символы client id вне `A-Z a-z 0-9 . _ -`
заменяются, а к имени добавляется короткий хеш. Браузер не разделяет cookie по
портам, поэтому приложения на одном hostname различаются только client id.
Чужие cookie модуль не читает и не стирает, даже если не может их
расшифровать. Все cookie имеют `Secure; HttpOnly; SameSite=Lax; Path=/` без
Domain. Cookie с legacy-именами на HTTPS не читаются, даже если корректно
зашифрованы. Только для `http://localhost` и `http://127.0.0.1` используются
имена без `__Host-` и Secure, например `auth_session.nextjs-demo`.

Cookie сессии вместе с именем не может быть больше 4000 байт: браузер молча
выбросил бы её, и вход пошёл бы по кругу. Роли в ней отдельно не хранятся, они
читаются из access-токена. Без ролей cookie весит около 1,3 КБ, каждая роль
длиной 20 символов добавляет примерно 40 байт, так что предел — порядка
65 таких ролей (раньше — около 45). Если сессия всё же не помещается, callback показывает страницу
ошибки с просьбой сообщить администратору, метку тихой проверки не ставит и
отзывает выданные токены. Refresh в такую сессию завершает её так же, как
`invalid_grant`. Уменьшите число ролей пользователя или длину их имён.

Новый sealed-конверт — v2 со сроком жизни. Конверты v1 не принимаются:
после обновления модуля пользователь входит заново. То же при переходе на
имена с суффиксом client id или смене `AUTH_CLIENT_ID`: прежнюю cookie модуль
не читает и не трогает, она истечёт сама. При живой SSO-сессии новый вход
проходит тихо. При обновлении всех
экземпляров приложения используйте одну версию модуля; старые экземпляры
не понимают новые cookies. Примеры в репозитории должны быть синхронизированы
с модулем перед их использованием.

## Выход

Обычная ссылка `<a href="/api/auth/logout">Выйти</a>` открывает подтверждение.
GET и HEAD не отзывают сессию; HEAD получает 405. Подтверждение отправляет POST
с проверкой Origin, CSRF-cookie и запечатанного токена на 10 минут. После него
модуль ограниченно по времени отзывает refresh, помечает его закрытым (см.
«Сроки и ошибки сессии»), очищает локальную сессию и активные flow из запроса,
затем ведёт на `/logout` Auth V3. Backend может
запросить отдельное подтверждение завершения общей SSO-сессии. Если его не
завершить, следующий тихий вход сможет снова использовать оставшуюся SSO.

Guard никогда не обновляет сессию на маршрутах модуля, поэтому не дописывает
свежую cookie поверх результата logout. Если revoke недоступен, локальный
выход всё равно завершается; удалённая сессия завершается при успешном отзыве
или по правилам Auth V3. Ограничение для нескольких процессов описано в
«Сроки и ошибки сессии».

Если страница подтверждения выхода открыта дольше 10 минут (или в другой
вкладке, где cookie уже нет), POST возвращает страницу «Страница выхода
устарела» со ссылкой на новое подтверждение, а не голый `Forbidden`. Чужой
Origin по-прежнему получает `Forbidden`.

Если пользователь нажал «Отказаться» на экране подтверждения входа, callback
показывает страницу об отказе со ссылкой «Попробовать снова», а не пустой
сбой.

## Другие серверы и проверки

`createSessionGuard()` возвращает `pass` с `user`, `setCookies` и
`unavailable: true` при временном сбое refresh, либо `deny` с готовым
`response`. Переносите результат guard и в контекст текущего запроса,
и в cookies ответа. `createAuthHandlers()` экспортирует GET и POST.
Ответы авторизации не должны кэшироваться; модуль ставит `Cache-Control: no-store`.

Проверки из корня репозитория:

```sh
npm run typecheck:module
npm run typecheck
npm test -- tests/module
npm run test:browser
```

`npm run test:browser` проверяет выход в настоящем Chromium через Playwright:
после «Выйти» браузер должен дойти до `/logout` сервиса. Страница
подтверждения ставит CSP `form-action`, а Chrome применяет его и к редиректу
после отправки формы, поэтому в нём разрешён origin `AUTH_URL`. Перед первым
запуском поставьте браузер: `npx playwright install chromium`.

Регрессии проверяют временные ошибки и отзыв, самостоятельный `/me`,
серверный TTL, несколько вкладок и PKCE/state, Hono, logout и Next.js.
Runtime-тест Next использует установленные зависимости `examples/nextjs-demo`:
в отдельном worktree путь можно задать через `AUTH_TEST_NEXT_DEMO`. Используются
настоящие NextRequest/NextResponse, request store, `headers()`/`cookies()` и
React SSR. Без установленного demo этот набор пропускается; остальные тесты
не требуют Next. Это не полноценный браузерный E2E и не production-проверка.
