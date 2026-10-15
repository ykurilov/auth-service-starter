import { createPool } from './pool.js';
import { runMigrations } from './migrate.js';

// Тонкий CLI: читает DATABASE_URL, применяет миграции из ./migrations и
// закрывает пул. Запускается на собранном dist (см. npm-скрипт "migrate").
async function main(): Promise<void> {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('DATABASE_URL не задан');
    process.exit(1);
  }
  const db = createPool(databaseUrl);
  try {
    const applied = await runMigrations(db, 'migrations');
    console.log(`Применено миграций: ${applied}`);
  } finally {
    await db.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
