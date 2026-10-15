import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { FastifyInstance } from 'fastify';

// Отдача design-system.css (дизайн-система LaunchLab) страницам сервиса.
// В репозитории лежит копия из «Дизайн-система LaunchLab/design-system.css»:
// линковать соседнюю папку воркспейса нельзя — сервис работает на удалённом
// сервере. Обновление — заново скопировать файл и задеплоить.
// Каталог ./assets читается от корня запуска — та же конвенция, что у
// ./migrations. Читаем один раз при старте: файл меняется только с релизом.
export function registerAssets(app: FastifyInstance): void {
  const css = readFileSync(resolve(process.cwd(), 'assets/design-system.css'), 'utf8');
  app.get('/assets/design-system.css', async (_req, reply) =>
    reply
      .type('text/css; charset=utf-8')
      .header('cache-control', 'public, max-age=3600')
      .send(css),
  );
}
