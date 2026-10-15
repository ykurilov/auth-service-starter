import { cp, mkdir } from 'node:fs/promises';
for (const target of ['examples/nextjs-demo/src/auth', 'examples/hono-vite-demo/server/auth']) {
  await mkdir(target, { recursive: true });
  await cp('module/server', target, { recursive: true });
}
await cp('module/browser/auth-client.ts', 'examples/hono-vite-demo/src/auth-client.ts');
console.log('Копии модуля в примерах обновлены.');
