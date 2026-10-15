import { createPool } from './pool.js';
import { runRevoke } from './rotate-key.js';

// Тонкий CLI аварийного отзыва ключа подписи: `revoke-key <kid>`.
// Помечает ключ revoked_at; на следующем старте сервис выкинет его из набора
// верификации. Отзывать можно только не-active ключ (сначала rotate-key).
// Приватный ключ/PEM не печатается.
async function main(): Promise<void> {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('DATABASE_URL не задан');
    process.exit(1);
  }
  const kid = process.argv[2];
  if (!kid) {
    console.error('Использование: revoke-key <kid>');
    process.exit(1);
  }
  const db = createPool(databaseUrl);
  try {
    await runRevoke(db, kid, new Date());
    console.log(`Ключ отозван: ${kid}. Перезапустите сервис, чтобы отзыв вступил в силу.`);
  } finally {
    await db.close();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
