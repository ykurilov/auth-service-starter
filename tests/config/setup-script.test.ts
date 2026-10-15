import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

describe('setup creates isolated installation secrets', () => {
  it('генерирует разные секреты, ограничивает права и не перезаписывает файл', () => {
    const dir = mkdtempSync(join(tmpdir(), 'auth-setup-test-'));
    try {
      const output = join(dir, '.env');
      const args = [resolve('scripts/setup.mjs'), '--issuer', 'https://auth.example.com', '--from', 'auth@example.com', '--output', output];
      const first = spawnSync(process.execPath, args, { encoding: 'utf8' });
      expect(first.status).toBe(0);
      const content = readFileSync(output, 'utf8');
      const password = content.match(/^POSTGRES_PASSWORD=(.+)$/m)![1]!;
      const token = content.match(/^ADMIN_API_TOKEN=(.+)$/m)![1]!;
      expect(password).toHaveLength(64);
      expect(token).toHaveLength(64);
      expect(password).not.toBe(token);
      expect(first.stdout).not.toContain(password);
      expect(first.stdout).not.toContain(token);
      if (process.platform !== 'win32') expect(statSync(output).mode & 0o777).toBe(0o600);
      const second = spawnSync(process.execPath, args, { encoding: 'utf8' });
      expect(second.status).toBe(1);
      expect(readFileSync(output, 'utf8')).toBe(content);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  it('не создаёт конфигурацию с внешним HTTP origin', () => {
    const result = spawnSync(process.execPath, [resolve('scripts/setup.mjs'), '--issuer', 'http://auth.example.com'], { encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('HTTPS');
  });
});
