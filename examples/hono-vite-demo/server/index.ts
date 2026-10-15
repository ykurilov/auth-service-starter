import { existsSync } from 'node:fs';
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { Hono } from 'hono';
import { createHonoAuth } from './auth/hono.js';

// .env.local имеет приоритет; шаблон .env.example можно скопировать в .env.
const envFile = existsSync('.env.local') ? '.env.local' : '.env';
if (existsSync(envFile)) process.loadEnvFile(envFile);

const production = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT ?? 3008);

// /api/notes отдаёт данные только вошедшему (запрос данных без входа — 401).
// /cabinet.html защищён на сервере в боевом режиме, когда страницы отдаёт
// Hono; в разработке страницы отдаёт Vite, и кабинет сам зовёт requireUser().
const auth = createHonoAuth({ env: process.env, protect: ['/api/notes', '/cabinet.html'] });

const app = new Hono();
app.use(auth.guard);
app.on(['GET', 'POST'], '/api/auth/*', auth.routes);

app.get('/api/notes', async (c) => {
  const user = await auth.user(c);
  if (!user) return c.json({ error: 'unauthenticated' }, 401);
  return c.json({ notes: [`Заметка для ${user.name ?? user.email ?? user.id}`] });
});

if (production) app.use('*', serveStatic({ root: './dist' }));

serve({ fetch: app.fetch, port }, () => {
  console.log(`Сервер Hono: http://localhost:${port}`);
});
