import { describe, it, expect, afterAll } from 'vitest';
import { bootstrap } from '../../src/index.js';
import { createMemDb } from '../helpers/pg-mem-db.js';
import { PgSigningKeyStore } from '../../src/adapters/repository/pg/pg-signing-key-store.js';
import { generateSigningKeyPem } from '../../src/domain/tokens/signing-key.js';
import type { Db } from '../../src/adapters/db/pool.js';

const ENV = {
  PUBLIC_ISSUER_URL: 'https://auth.example',
  KEY_AUTOGENERATE: 'true',
  LOG_LEVEL: 'silent',
  DATABASE_URL: 'postgres://mem',
  SSO_COOKIE_SECURE: 'false',
  CLIENTS_JSON: '[]',
} as NodeJS.ProcessEnv;

const ISSUE_INPUT = {
  userId: 'user-1',
  clientId: 'shop',
  provider: 'email',
  roles: ['student'],
  profile: { email: 'u@example.com', emailVerified: true, name: 'U' },
  scope: 'openid profile email',
};

// Хранилище ключей подписи в БД: JWKS отдаёт все ключи, bootstrap сидирует ключ
// на чистой БД и переиспользует его при рестарте, а после ротации верификация
// находит старый ключ по kid. Один экземпляр Db на весь тест (pg-mem держит
// состояние в памяти клиента).
describe('signing keys из БД (pg-mem)', () => {
  const db: Db = createMemDb();

  afterAll(async () => {
    await db.close();
  });

  async function jwks(app: { inject: (o: { method: string; url: string }) => Promise<{ json: () => { keys: Array<{ kid: string }> } }> }) {
    const res = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    return res.json().keys;
  }

  it('сидирует ключ, переживает рестарт и добавляет ключ при ротации', async () => {
    // 1. Первый bootstrap на чистой БД → ровно один ключ в JWKS.
    const boot1 = await bootstrap(ENV, { dbFactory: () => db });
    const keys1 = await jwks(boot1.app);
    expect(keys1).toHaveLength(1);
    const firstKid = keys1[0]!.kid;
    // Токен, выпущенный ДО ротации активным (первым) ключом.
    const issued = await boot1.tokenService.issueAccessAndId(ISSUE_INPUT);
    await boot1.app.close();

    // 2. Второй bootstrap на ТОЙ ЖЕ БД → тот же kid (ключ не сгенерился заново).
    const boot2 = await bootstrap(ENV, { dbFactory: () => db });
    const keys2 = await jwks(boot2.app);
    expect(keys2).toHaveLength(1);
    expect(keys2[0]!.kid).toBe(firstKid);
    await boot2.app.close();

    // 3. Ротация: новый ключ становится активным, прежний → retired.
    const gen = await generateSigningKeyPem();
    const newActive = {
      ...gen,
      status: 'active' as const,
      createdAt: new Date(),
      retiredAt: null,
      revokedAt: null,
    };
    await new PgSigningKeyStore(db).rotate(newActive, new Date());

    // 4. Третий bootstrap на той же БД → в JWKS оба ключа (старый + новый).
    const boot3 = await bootstrap(ENV, { dbFactory: () => db });
    const keys3 = await jwks(boot3.app);
    expect(keys3).toHaveLength(2);
    const kids = keys3.map((k) => k.kid).sort();
    expect(kids).toEqual([firstKid, newActive.kid].sort());

    // 5. Верификация по kid: токен, выпущенный старым ключом до ротации,
    // проверяется третьим bootstrap'ом (retired-ключ найден среди
    // verificationKeys), а не отвергается как unknown kid.
    const claims = await boot3.tokenService.verifyAccessToken(issued.accessToken);
    expect(claims.sub).toBe('user-1');
    await boot3.app.close();
  });
});
