import { describe, it, expect } from 'vitest';
import { generateSsoToken } from '../../../src/domain/sso/sso-session.js';

describe('generateSsoToken', () => {
  it('возвращает base64url-строку длиннее 20 символов', () => {
    const token = generateSsoToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(token.length).toBeGreaterThan(20);
  });

  it('два вызова дают разные токены', () => {
    expect(generateSsoToken()).not.toBe(generateSsoToken());
  });
});
