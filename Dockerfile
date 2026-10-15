# --- Сборка ---
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

# --- Рантайм ---
FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
# Метка для scripts/client.mjs: внутри контейнера сервис слушает PORT, а не HOST_PORT.
ENV AUTH_SERVICE_CONTAINER=1
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
# Миграции нужны в образе: runMigrations читает каталог ./migrations при старте
# (MIGRATE_ON_BOOT) и в CLI `npm run migrate`.
COPY migrations ./migrations
# Статика страниц: design-system.css отдаётся маршрутом /assets/design-system.css.
COPY assets ./assets
# CLI управления приложениями доступен и внутри контейнера.
COPY scripts ./scripts

# Не запускаемся под root.
USER node

# Проверка живости: контейнер здоров, пока отвечает /live.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3016)+'/live').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/src/index.js"]
