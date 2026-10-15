import { describe, it, expect } from 'vitest';
import { normalizeEmail } from '../../../src/domain/identity/user.js';

describe('normalizeEmail', () => {
  it('приводит к нижнему регистру и обрезает пробелы', () => {
    expect(normalizeEmail('  Alice@Example.COM ')).toBe('alice@example.com');
  });

  it('идемпотентна', () => {
    const once = normalizeEmail('User@Mail.ru');
    expect(normalizeEmail(once)).toBe(once);
  });
});
