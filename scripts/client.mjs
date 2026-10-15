import { randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';
const [action, value, ...rest] = process.argv.slice(2);
if (action === 'cookie-secret') {
  console.log(randomBytes(32).toString('hex'));
  process.exit(0);
}
if (!['list', 'add', 'delete'].includes(action) || (action !== 'list' && !value)) {
  console.error('npm run client -- list | add https://app.example.com [--id client-id] [--external] [--email-only] | delete client-id | cookie-secret');
  process.exit(1);
}
try {
  const { values } = parseArgs({ args: rest, options: {
    id: { type: 'string' }, external: { type: 'boolean' }, 'email-only': { type: 'boolean' },
  } });
  // CLI обращается к самому процессу сервиса: публичный адрес может ещё не
  // работать до настройки nginx и сертификата. ADMIN_API_URL переопределяет
  // адрес. На хосте сервис опубликован на HOST_PORT; внутри контейнера (образ
  // ставит AUTH_SERVICE_CONTAINER=1) тот же .env содержит HOST_PORT, но
  // процесс слушает PORT.
  const inContainer = process.env.AUTH_SERVICE_CONTAINER === '1';
  const port = (!inContainer && process.env.HOST_PORT) || process.env.PORT || 3016;
  const adminApi = new URL(process.env.ADMIN_API_URL || `http://127.0.0.1:${port}`);
  if (adminApi.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(adminApi.hostname)) throw new Error('Для удалённого сервиса требуется HTTPS');
  if (!process.env.ADMIN_API_TOKEN) throw new Error('ADMIN_API_TOKEN не задан');
  let body;
  if (action === 'add') {
    const base = new URL(value);
    if (base.username || base.password || base.pathname !== '/' || base.search || base.hash ||
      (base.protocol !== 'https:' && !(base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)))) {
      throw new Error('Укажите HTTPS origin приложения без пути (HTTP только localhost)');
    }
    const type = values.external ? 'external' : 'internal';
    body = { id: values.id || base.hostname, type, redirectUris: [base.origin + '/api/auth/callback'],
      postLogoutRedirectUris: [base.origin + '/'], allowedProviders: values.external || values['email-only'] ? ['email'] : ['email', 'google'] };
  }
  const path = action === 'delete' ? '/admin/clients/' + encodeURIComponent(value) : '/admin/clients';
  const response = await fetch(new URL(path, adminApi), {
    method: action === 'add' ? 'POST' : action === 'delete' ? 'DELETE' : 'GET',
    headers: { authorization: 'Bearer ' + process.env.ADMIN_API_TOKEN, ...(body ? { 'content-type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(15_000), redirect: 'error',
  });
  if (!response.ok) throw new Error('Admin API вернул HTTP ' + response.status);
  if (response.status !== 204) console.log(JSON.stringify(await response.json(), null, 2));
  else console.log('Приложение удалено.');
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
