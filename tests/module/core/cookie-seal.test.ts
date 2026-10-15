import { describe, it, expect } from 'vitest';
import { seal, unseal } from '../../../module/server/core/cookie-seal.js';

const SECRET = 'секрет-достаточной-длины-32-символа-минимум-1234567890';

describe('cookie-seal', () => {
  it('seal -> unseal возвращает исходный объект', async () => {
    const data = { user: { id: 'u1', roles: ['admin'] }, accessToken: 'x.y.z' };
    const sealed = await seal(data, SECRET);
    expect(typeof sealed).toBe('string');
    expect(await unseal(sealed, SECRET)).toEqual(data);
  });

  it('два запечатывания одного значения различаются (свежий iv)', async () => {
    const a = await seal({ a: 1 }, SECRET);
    const b = await seal({ a: 1 }, SECRET);
    expect(a).not.toBe(b);
  });

  it('unseal под другим секретом -> null', async () => {
    const sealed = await seal({ a: 1 }, SECRET);
    expect(await unseal(sealed, SECRET + 'x')).toBeNull();
  });

  it('порча шифротекста -> null (не бросает)', async () => {
    const sealed = await seal({ a: 1 }, SECRET);
    const broken = sealed.slice(0, -3) + (sealed.endsWith('A') ? 'BBB' : 'AAA');
    expect(await unseal(broken, SECRET)).toBeNull();
  });

  it('мусор вместо запечатанной строки -> null', async () => {
    expect(await unseal('не-запечатанная-строка', SECRET)).toBeNull();
    expect(await unseal('', SECRET)).toBeNull();
  });

  it('неверная версия конверта -> null', async () => {
    const sealed = await seal({ a: 1 }, SECRET);
    // Первый сегмент — версия. Портим её.
    const parts = sealed.split('.');
    parts[0] = 'v9';
    expect(await unseal(parts.join('.'), SECRET)).toBeNull();
  });
});
