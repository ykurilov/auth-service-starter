import { describe, it, expect } from 'vitest';
import {
  ClientValidationError,
  assertProvidersAllowedForType,
  clientCreateSchema,
  isAllowedRedirectUri,
} from '../../../src/domain/clients/client-validation.js';

describe('assertProvidersAllowedForType', () => {
  it('external + google → ClientValidationError', () => {
    expect(() => assertProvidersAllowedForType('external', ['email', 'google'])).toThrow(
      ClientValidationError,
    );
  });

  it('internal + google → ок', () => {
    expect(() => assertProvidersAllowedForType('internal', ['google'])).not.toThrow();
  });

  it('external без google → ок', () => {
    expect(() => assertProvidersAllowedForType('external', ['email', 'vk'])).not.toThrow();
  });
});

describe('clientCreateSchema', () => {
  const valid = {
    id: 'app1',
    type: 'external',
    redirectUris: ['https://app1.example/cb'],
    allowedProviders: ['email'],
  };

  it('принимает валидный вход', () => {
    expect(clientCreateSchema.parse(valid)).toMatchObject({ id: 'app1' });
  });

  it('отклоняет пустой redirectUris', () => {
    expect(() => clientCreateSchema.parse({ ...valid, redirectUris: [] })).toThrow();
  });

  it('отклоняет невалидный URL', () => {
    expect(() =>
      clientCreateSchema.parse({ ...valid, redirectUris: ['not-a-url'] }),
    ).toThrow();
  });

  it('отклоняет неизвестного провайдера', () => {
    expect(() =>
      clientCreateSchema.parse({ ...valid, allowedProviders: ['facebook'] }),
    ).toThrow();
  });

  it('отклоняет http redirectUris', () => {
    const r = clientCreateSchema.safeParse({ ...valid, redirectUris: ['http://evil.com/cb'] });
    expect(r.success).toBe(false);
  });

  it('отклоняет http postLogoutRedirectUris', () => {
    const r = clientCreateSchema.safeParse({
      ...valid,
      postLogoutRedirectUris: ['http://evil.com/'],
    });
    expect(r.success).toBe(false);
  });
});

describe('isAllowedRedirectUri', () => {
  it('https разрешён', () => {
    expect(isAllowedRedirectUri('https://app.example.com/api/auth/callback')).toBe(true);
  });

  it('http запрещён для обычных хостов', () => {
    expect(isAllowedRedirectUri('http://evil.com/cb')).toBe(false);
  });

  it('http разрешён для localhost и 127.0.0.1', () => {
    expect(isAllowedRedirectUri('http://localhost:3000/api/auth/callback')).toBe(true);
    expect(isAllowedRedirectUri('http://127.0.0.1:3000/cb')).toBe(true);
  });

  it('мусор не проходит', () => {
    expect(isAllowedRedirectUri('not-a-url')).toBe(false);
  });
});
