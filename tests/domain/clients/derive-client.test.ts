import { describe, it, expect } from 'vitest';
import { deriveClientFromBaseUrl } from '../../../src/domain/clients/derive-client.js';

describe('deriveClientFromBaseUrl', () => {
  it('по умолчанию internal с email+google (наши приложения)', () => {
    const c = deriveClientFromBaseUrl({ baseUrl: 'https://app.example.com' });
    expect(c).toEqual({
      id: 'app.example.com',
      type: 'internal',
      redirectUris: ['https://app.example.com/api/auth/callback'],
      allowedProviders: ['email', 'google'],
      postLogoutRedirectUris: ['https://app.example.com/'],
    });
  });

  it('external по умолчанию — только email (google запрещён стороннему)', () => {
    const c = deriveClientFromBaseUrl({ baseUrl: 'https://third.example', type: 'external' });
    expect(c.type).toBe('external');
    expect(c.allowedProviders).toEqual(['email']);
  });

  it('отбрасывает path/query из baseUrl (берёт только origin)', () => {
    const c = deriveClientFromBaseUrl({ baseUrl: 'https://app.example.com/some/path?x=1' });
    expect(c.redirectUris).toEqual(['https://app.example.com/api/auth/callback']);
  });

  it('уважает явный allowedProviders (отключение google при желании)', () => {
    const c = deriveClientFromBaseUrl({
      baseUrl: 'https://in.example.com',
      allowedProviders: ['email'],
    });
    expect(c.type).toBe('internal');
    expect(c.allowedProviders).toEqual(['email']);
  });
});
