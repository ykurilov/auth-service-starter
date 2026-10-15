# Развёртывание и обслуживание

Основной путь установки - Docker Compose на Linux VPS. Сначала заполните `.env` по README. Ключи и БД принадлежат вашей установке; внешние адреса в примерах заменяются вашими.

## HTTPS через nginx

Установите Docker Engine с Compose v2 по [официальной инструкции Docker](https://docs.docker.com/engine/install/ubuntu/) и nginx средствами своей системы. Направьте DNS-запись `auth.example.com` на VPS. В шаблоне `deploy/nginx/auth-v3.conf` замените домен и при необходимости порт, затем подключите файл:

```sh
sudo cp deploy/nginx/auth-v3.conf /etc/nginx/sites-available/auth.conf
sudo ln -s /etc/nginx/sites-available/auth.conf /etc/nginx/sites-enabled/auth.conf
sudo nginx -t
sudo systemctl reload nginx
```

Для TLS установите certbot по [инструкции для своей ОС](https://certbot.eff.org/instructions), затем:

```sh
sudo certbot --nginx -d auth.example.com
```

Включите предложенный редирект HTTP -> HTTPS. В `.env` должны быть `PUBLIC_ISSUER_URL=https://auth.example.com` и `SSO_COOKIE_SECURE=true`. Проверка:

```sh
curl --fail https://auth.example.com/live
curl --fail https://auth.example.com/.well-known/openid-configuration
```

`issuer` и адреса discovery должны указывать на ваш публичный HTTPS-домен. Вход начинается из подключённого приложения, а не с корня сервиса.

## Доверенные прокси и порты

Приложение в compose опубликовано только на `127.0.0.1:${HOST_PORT:-3016}`. PostgreSQL и Redis наружу не опубликованы. Настройка `PORT` внутри compose закреплена на 3016; для изменения внешнего порта используется HOST_PORT.

nginx на хосте приходит в контейнер с адреса Docker gateway. По умолчанию выделена сеть `172.30.240.0/24`, gateway `172.30.240.1`; `TRUST_PROXY=loopback,172.30.240.1`. Если эта подсеть занята, измените DOCKER_SUBNET/DOCKER_GATEWAY и соответствующий адрес в TRUST_PROXY. При пересоздании сети предварительно остановите compose без удаления volumes.

Ошибка `Pool overlaps with other one on this address space` означает конфликт с существующей Docker-сетью. После проверки `docker network inspect` выберите свободную приватную подсеть и согласованно измените три строки `.env`, например:

```dotenv
DOCKER_SUBNET=10.250.240.0/24
DOCKER_GATEWAY=10.250.240.1
TRUST_PROXY=loopback,10.250.240.1
```

Пример подходит, только если эта подсеть свободна в вашей сети.

Для другого прокси укажите его IP/CIDR. Старые true/числа в TRUST_PROXY поддерживаются только для loopback; они не означают доверие произвольному источнику. На новом Fastify числовой hop-count напрямую не передаётся. Не разрешайте доверие всем адресам, а клиентский X-Forwarded-For перезаписывайте на границе.

TOKEN_RATE_LIMIT задаёт широкий бюджет token endpoint за 15 минут на исходящий IP серверных приложений. По умолчанию 10000; рассчитывайте значение по своему числу активных сессий и количеству приложений. Лимиты отправки и проверки одноразовых кодов считаются отдельно.

## Приложения и локальные демо

Для приложения на отдельном hostname достаточно краткой регистрации:

```sh
docker compose exec app node scripts/client.mjs add https://app.example.com
```

Для двух демо на одном localhost нужны разные client id. Полная форма Admin API принимает `id`, `type`, `redirectUris`, `allowedProviders`, `postLogoutRedirectUris`. Токен берётся из ADMIN_API_TOKEN и передаётся только в Authorization: Bearer; не помещайте его в URL и не сохраняйте в репозитории.

Пример тела регистрации Next.js-демо:

```json
{"id":"nextjs-demo","type":"internal","redirectUris":["http://localhost:3005/api/auth/callback"],"allowedProviders":["email"],"postLogoutRedirectUris":["http://localhost:3005/"]}
```

Для Hono аналогично: `id=hono-vite-demo`, порт 3007. Эти id уже указаны в `.env.example` примеров. Можно также добавить оба объекта в CLIENTS_JSON перед первым запуском; CLIENTS_JSON применяется однократно при первом запуске новой БД. После этого добавление, изменение и удаление выполняются через Admin API или client.mjs, независимо от содержимого CLIENTS_JSON.

## Резервные копии

Дамп содержит персональные данные и ключи подписи. Храните его зашифрованным отдельно от VPS, ограничьте доступ и срок хранения. Не добавляйте его в GitHub.

```sh
mkdir -p backups
chmod 700 backups
docker compose exec -T postgres pg_dump -U authv3 -d authv3 -Fc > backups/auth.dump
chmod 600 backups/auth.dump
```

Проверяйте восстановление на отдельной БД. На новом сервере восстановите `.env` из защищённой копии и поднимите **только PostgreSQL**. Не запускайте app: при старте он заполняет новую БД миграциями и ключами. Команды ниже предназначены для пустого PostgreSQL volume новой установки:

```sh
docker compose up -d --wait postgres
docker compose exec -T postgres pg_restore -U authv3 -d authv3 --no-owner --single-transaction --exit-on-error < backups/auth.dump
docker compose up -d --build
```

Не выполняйте восстановление поверх работающей БД без плана переноса: существующие таблицы и активные сессии могут конфликтовать. Также сохраните `.env` в защищённом хранилище. Redis здесь сохраняет лимиты через AOF, но резервной копией пользователей остаётся PostgreSQL.

## Обновление

Перед обновлением сохраните дамп и прочитайте release notes о миграциях. В своей копии репозитория:

```sh
git pull --ff-only
docker compose up -d --build
docker compose ps
curl --fail http://127.0.0.1:3016/live
```

Миграции применяются при старте. Возврат старого образа после изменения схемы может потребовать отдельной обратной миграции или восстановления дампа; автоматическое удаление данных не выполняется.

## Ключи подписи

Обычная ротация оставляет прежний public key для проверки ещё действующих JWT:

```sh
docker compose exec app npm run rotate-key
docker compose restart app
```

При утечке выполните ротацию, затем отзыв скомпрометированного retired kid:

```sh
docker compose exec app npm run revoke-key -- OLD_KID
docker compose restart app
```

Отозвать active key нельзя: сначала создаётся новый. Процесс загружает ключи при старте, поэтому перезапуск обязателен. Учтите кэш JWKS в подключённых приложениях и срок уже выданных access JWT. Команды выполняют готовые CLI из dist и не требуют TypeScript в контейнере.

## Локальная разработка без контейнера приложения

Используйте Node.js 22.12+. В `.env` задайте DATABASE_URL/REDIS_URL своих локальных сервисов; compose не публикует их порты. Для данных разработки используйте отдельную базу.

```sh
npm ci
npm run build
npm start
```

In-memory режим без DATABASE_URL предназначен только для тестов и разработки: пользователи и ключи в нём исчезают при перезапуске. Production требует PostgreSQL и настроенную почту.
