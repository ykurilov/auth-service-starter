import { describe, it, expect } from 'vitest';
import { InvalidRefreshTokenError, RefreshTokenReuseError } from '../../../src/domain/sessions/errors.js';

describe('sessions errors', () => {
  it('InvalidRefreshTokenError — это Error с именем', () => {
    const e = new InvalidRefreshTokenError();
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('InvalidRefreshTokenError');
  });

  it('RefreshTokenReuseError наследует InvalidRefreshTokenError', () => {
    const e = new RefreshTokenReuseError();
    expect(e).toBeInstanceOf(InvalidRefreshTokenError);
    expect(e.name).toBe('RefreshTokenReuseError');
  });
});
