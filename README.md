# Auth Service Starter

Сервис единого входа, который работает на вашем сервере и хранит пользователей в вашей PostgreSQL. Подходит для нескольких собственных приложений: пользователь входит по коду из письма или через Google, а приложения получают сессию через OIDC Authorization Code + PKCE.

В комплекте сервер на TypeScript/Fastify, Docker Compose, модуль подключения Next.js/Hono и два работающих примера. Лицензия [MIT](LICENSE) разрешает использование и изменение, в том числе в коммерческих проектах.

## Что понадобится

- VPS с Docker Engine и Docker Compose v2. Для подготовки настроек - Node.js 22.12+; его можно установить на рабочем компьютере.
- Домен для входа, например `auth.example.com`, направленный на VPS. Публичная установка работает по HTTPS.
- Собственный аккаунт Resend, API-ключ и подтверждённый домен отправителя. Без почтового провайдера коды не доставляются. Ключ Google нужен только при включении Google-входа.

Начать можно на локальном компьютере с Docker Desktop; публичный адрес и HTTPS понадобятся перед подключением реальных пользователей.

## Установка

```sh
git clone https://github.com/ykurilov/auth-service-starter.git
cd auth-service-starter
node scripts/setup.mjs --issuer https://auth.example.com --from auth@example.com
```

Команда создаёт `.env` с уникальными паролем базы и токеном администратора, не выводя их в консоль. Существующий файл она не перезаписывает. В `.env` заполните `RESEND_API_KEY`; `EMAIL_FROM` должен принадлежать подтверждённому в Resend домену. Замените `EMAIL_APP_NAME` названием своего проекта.

```sh
docker compose up -d --build
docker compose ps
curl --fail http://127.0.0.1:3016/live
```

Ожидаемый ответ проверки: `{"status":"ok"}`. Схема PostgreSQL и ключ подписи создаются при первом запуске. Если приложение завершается, причина видна в `docker compose logs --tail=50 app`: production-запуск требует настроенную почту и постоянную БД.

Приложение слушает только `127.0.0.1`, PostgreSQL и Redis доступны внутри Docker. Публичный HTTPS настраивается через nginx на VPS; готовый шаблон и команды находятся в [инструкции развёртывания](docs/DEPLOY.md). Внешний адрес в `.env` должен в точности совпадать с HTTPS-адресом сервиса.

Для локальной разработки создайте настройки с `--issuer http://localhost:3016`. Setup отключит Secure-cookie для локального HTTP. Почта всё равно требует собственного Resend; тесты используют fake mailer и настоящих писем не отправляют.

## Подключение приложения

Зарегистрируйте его публичный адрес через CLI, который берёт токен администратора из окружения контейнера:

```sh
docker compose exec app node scripts/client.mjs add https://app.example.com
```

Будут зарегистрированы callback `/api/auth/callback` и адрес возврата после выхода `/`. По умолчанию client id равен hostname приложения. Несколько приложений на одном hostname с разными портами регистрируйте полной формой Admin API с разными id; в модуле явно задавайте `AUTH_CLIENT_ID`.

В окружении самого приложения задайте:

```dotenv
AUTH_URL=https://auth.example.com
AUTH_APP_URL=https://app.example.com
AUTH_COOKIE_SECRET=<собственный случайный секрет не короче 32 символов>
```

Секрет cookie должен отличаться у разных приложений. Его можно сгенерировать командой `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"` и сохранить в закрытых настройках своего хостинга.

Инструкции и код подключения находятся в [module/README.md](module/README.md). Для Next.js копируется `module/server`, для Hono + Vite дополнительно нужен `module/browser/auth-client.ts`. Примеры: [Next.js](examples/nextjs-demo) и [Hono + Vite](examples/hono-vite-demo).

Оба примера используют `.env.example`. После копирования в локальный `.env` задайте адрес своего сервиса и уникальный секрет cookie. Для регистрации демо:

```sh
docker compose exec app node scripts/client.mjs add http://localhost:3005 --id nextjs-demo --email-only
docker compose exec app node scripts/client.mjs add http://localhost:3007 --id hono-vite-demo --email-only
```

Установите зависимости командой `npm ci` внутри примера. Next.js запускается через `npm run dev` на порту 3005; Hono + Vite - на 3007.

## Google и типы клиентов

В Google Cloud Console создайте OAuth Web Client и добавьте origin **сервиса входа** в Authorized JavaScript origins. Его Client ID запишите в `GOOGLE_CLIENT_ID`, затем пересоздайте контейнер приложения: `docker compose up -d app`.

`internal` означает приложение в вашей доверенной системе. Ему доступны email и, при настройке сервиса, Google. У `external` Google выключен политикой этого starter. Тихий вход для него не выдаёт код: модуль переходит к обычному входу с кнопкой согласия. Сохранённых согласий нет, поэтому подтверждение требуется при каждом новом входе во внешнее приложение. Типы клиентов не являются юридической оценкой допустимости провайдера в вашей стране.

Для стороннего Google-аккаунта с адресом вне Gmail/Google Workspace первый вход может потребовать код из письма: историческое подтверждение Google не всегда доказывает текущее владение сторонним ящиком.

## Обслуживание

```sh
docker compose exec app node scripts/client.mjs list
docker compose exec app node scripts/client.mjs delete app.example.com
docker compose exec app npm run rotate-key
docker compose restart app
```

Миграции и CLI выполняются из готового `dist`: TypeScript внутри рабочего контейнера не требуется. Правила аварийного отзыва ключа, обновления и резервного копирования описаны в [DEPLOY.md](docs/DEPLOY.md).

## Проверки и разработка

```sh
npm ci
npm run check
```

Без внешних сервисов проверяются доменная логика, HTTP, Pg-адаптеры на pg-mem и интеграции модулей. Для тестов настоящего PostgreSQL и Redis используются отдельные тестовые адреса `DATABASE_URL_TEST` и `REDIS_URL_TEST`; тестовая база должна быть изолирована от production. GitHub Actions запускает эти проверки на сервисных контейнерах.

Изменения `module/` переносятся в примеры командой `npm run sync-examples`. В уже развёрнутых сторонних приложениях копии обновляются отдельно.

## Границы проекта

Это самостоятельный сервер входа с ограниченным набором OIDC-возможностей, а не заявка на полную сертификацию OpenID. Парольный вход, ВК/Яндекс, интерфейс управления пользователями, MFA и готовая ролевая модель в starter не реализованы. Поле roles не заменяет проверку прав в вашем приложении.

Защищайте данные на сервере приложения, проверяя сессию или подпись, issuer, audience и срок access-токена. Браузерный `requireUser()` управляет интерфейсом и не заменяет серверную проверку. Уже выпущенный access JWT действует до истечения своего короткого срока; отзыв refresh прекращает дальнейшее обновление.

Модель безопасности и сообщение об уязвимости: [SECURITY.md](SECURITY.md). Изменения по итогам аудита: [HARDENING.md](docs/HARDENING.md).
