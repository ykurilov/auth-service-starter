import { describe, it, expect } from 'vitest';
import { generateRefreshToken } from '../../../src/domain/sessions/refresh-token.js';

describe('generateRefreshToken', () => {
  it('высокоэнтропийный base64url, каждый вызов уникален', () => {
    const a = generateRefreshToken();
    const b = generateRefreshToken();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(a.length).toBeGreaterThanOrEqual(43); // 32 байта base64url
  });
});
