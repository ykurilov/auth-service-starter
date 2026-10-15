import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { oauthErrorFor } from '../../../src/adapters/http/oauth-errors.js';
import { InvalidClientError, InvalidGrantError } from '../../../src/domain/login/errors.js';
import {
  InvalidRefreshTokenError,
  RefreshTokenReuseError,
} from '../../../src/domain/sessions/errors.js';

describe('oauthErrorFor', () => {
  it('InvalidGrantError → 400 invalid_grant', () => {
    expect(oauthErrorFor(new InvalidGrantError())).toEqual({
      status: 400,
      error: 'invalid_grant',
    });
  });

  it('InvalidRefreshTokenError → 400 invalid_grant', () => {
    expect(oauthErrorFor(new InvalidRefreshTokenError())).toEqual({
      status: 400,
      error: 'invalid_grant',
    });
  });

  it('RefreshTokenReuseError → 400 invalid_grant', () => {
    expect(oauthErrorFor(new RefreshTokenReuseError())).toEqual({
      status: 400,
      error: 'invalid_grant',
    });
  });

  it('InvalidClientError → 401 invalid_client', () => {
    expect(oauthErrorFor(new InvalidClientError())).toEqual({
      status: 401,
      error: 'invalid_client',
    });
  });

  it('ZodError (кривой ввод) → 400 invalid_request', () => {
    const parsed = z.object({ code: z.string() }).safeParse({});
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(oauthErrorFor(parsed.error)).toEqual({
        status: 400,
        error: 'invalid_request',
      });
    }
  });

  it('неизвестная ошибка → null (инфраструктурный сбой, пробрасывать)', () => {
    expect(oauthErrorFor(new Error('db down'))).toBeNull();
  });
});
