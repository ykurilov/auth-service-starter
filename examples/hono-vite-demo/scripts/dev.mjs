// Запускает сервер Hono и Vite вместе; Ctrl+C останавливает оба.
import { spawn } from 'node:child_process';

const processes = [
  spawn('npx', ['tsx', 'watch', 'server/index.ts'], { stdio: 'inherit' }),
  spawn('npx', ['vite'], { stdio: 'inherit' }),
];

function stopAll() {
  for (const child of processes) child.kill('SIGTERM');
}

for (const child of processes) {
  child.on('exit', (code) => {
    stopAll();
    process.exitCode = code ?? 0;
  });
}
process.on('SIGINT', stopAll);
process.on('SIGTERM', stopAll);
