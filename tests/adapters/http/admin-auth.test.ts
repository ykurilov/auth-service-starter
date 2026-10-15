import { describe, it, expect } from 'vitest';
import { checkAdminAuth } from '../../../src/adapters/http/admin-auth.js';

describe('checkAdminAuth', () => {
  it('верный токен → true', () => {
    expect(checkAdminAuth('Bearer secret', 'secret')).toBe(true);
  });

  it('неверный токен той же длины → false', () => {
    expect(checkAdminAuth('Bearer secreX', 'secret')).toBe(false);
  });

  it('без Bearer → false', () => {
    expect(checkAdminAuth('secret', 'secret')).toBe(false);
    expect(checkAdminAuth(undefined, 'secret')).toBe(false);
  });

  it('пустой expected → false', () => {
    expect(checkAdminAuth('Bearer secret', '')).toBe(false);
  });

  it('разная длина → false и не бросает', () => {
    expect(checkAdminAuth('Bearer short', 'muchlongertoken')).toBe(false);
  });
});
