import { randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ options: {
  issuer: { type: 'string', default: 'http://localhost:3016' },
  from: { type: 'string', default: 'auth@example.com' },
  app: { type: 'string' },
  output: { type: 'string', default: '.env' },
  help: { type: 'boolean', default: false },
} });
if (values.help) {
  console.log('node scripts/setup.mjs --issuer https://auth.example.com --from auth@example.com [--app https://app.example.com] [--output .env]');
  process.exit(0);
}
function origin(value, name) {
  const url = new URL(value);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || (url.protocol !== 'https:' && !(url.protocol === 'http:' && local))) {
    throw new Error(name + ': HTTPS обязателен, кроме localhost');
  }
  if (url.pathname !== '/' || url.search || url.hash) throw new Error(name + ': укажите origin без пути');
  return url;
}
try {
  const issuer = origin(values.issuer, 'issuer');
  if (!/^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/.test(values.from)) throw new Error('from: укажите один email-адрес');
  const local = issuer.protocol === 'http:';
  const clients = values.app ? [{ base: origin(values.app, 'app') }].map(({ base }) => ({
    id: base.hostname, type: 'internal', redirectUris: [base.origin + '/api/auth/callback'],
    postLogoutRedirectUris: [base.origin + '/'], allowedProviders: ['email', 'google'],
  })) : [];
  const content = [
    '# Создано setup. Секреты уникальны для этой установки; файл не коммитится.',
    'PORT=3016', 'HOST_PORT=3016', 'PUBLIC_ISSUER_URL=' + issuer.origin,
    'POSTGRES_PASSWORD=' + randomBytes(32).toString('hex'),
    'ADMIN_API_TOKEN=' + randomBytes(32).toString('hex'),
    'RESEND_API_KEY=', 'EMAIL_FROM=' + values.from, 'EMAIL_FROM_NAME=Auth Service',
    'EMAIL_APP_NAME=Моё приложение', 'GOOGLE_CLIENT_ID=',
    'CLIENTS_JSON=' + JSON.stringify(clients), 'MIGRATE_ON_BOOT=true',
    'SSO_COOKIE_SECURE=' + !local,
    '# nginx на хосте -> Docker gateway; для другого прокси укажите его IP/CIDR.',
    'TRUST_PROXY=loopback,172.30.240.1', 'DOCKER_SUBNET=172.30.240.0/24',
    'DOCKER_GATEWAY=172.30.240.1', 'ACCESS_TTL_SECONDS=900', 'ID_TTL_SECONDS=900',
    'LOG_LEVEL=info', '',
  ].join('\n');
  await writeFile(values.output, content, { flag: 'wx', mode: 0o600 });
  console.log('Создан ' + values.output + '. Пароли и токен администратора сгенерированы и не выведены в консоль.');
  console.log('Заполните RESEND_API_KEY и проверьте EMAIL_FROM перед отправкой писем.');
} catch (error) {
  console.error(error.code === 'EEXIST' ? 'Файл уже существует. Настройки не перезаписаны.' : error.message);
  process.exitCode = 1;
}
