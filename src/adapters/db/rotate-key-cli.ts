import { createPool } from './pool.js';
import { describeRotation, runRotate } from './rotate-key.js';

// Тонкий CLI: читает DATABASE_URL, ротирует ключ подписи и закрывает пул.
// Приватный ключ/PEM не печатается — только kid нового ключа и kid ключей,
// отправленных в retired (их передают в revoke-key при утечке).
// Запускается на собранном dist (см. npm-скрипт "rotate-key").
async function main(): Promise<void> {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('DATABASE_URL не задан');
    process.exit(1);
  }
  const db = createPool(databaseUrl);
  try {
    console.log(describeRotation(await runRotate(db, new Date())));
  } finally {
    await db.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
