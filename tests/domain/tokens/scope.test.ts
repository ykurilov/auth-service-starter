import { describe, it, expect } from 'vitest';
import { parseScopes, normalizeScope, profileForScope } from '../../../src/domain/tokens/scope.js';

const PROFILE = { email: 'user@x.com', emailVerified: true, name: 'Иван' };

describe('parseScopes', () => {
  it('openid присутствует всегда, даже если не запрошен', () => {
    expect(parseScopes('profile')).toEqual(new Set(['openid', 'profile']));
    expect(parseScopes('')).toEqual(new Set(['openid']));
    expect(parseScopes(undefined)).toEqual(new Set(['openid']));
  });

  it('неизвестные scope молча отбрасываются', () => {
    expect(parseScopes('openid email admin superuser')).toEqual(
      new Set(['openid', 'email']),
    );
  });

  it('дубликаты и лишние пробелы схлопываются', () => {
    expect(parseScopes('  email   email  profile ')).toEqual(
      new Set(['openid', 'email', 'profile']),
    );
  });
});

describe('normalizeScope', () => {
  it('возвращает стабильный порядок openid → profile → email', () => {
    expect(normalizeScope('email profile openid')).toBe('openid profile email');
    expect(normalizeScope('email')).toBe('openid email');
  });

  it('пустой/undefined → только openid', () => {
    expect(normalizeScope('')).toBe('openid');
    expect(normalizeScope(undefined)).toBe('openid');
  });
});

describe('profileForScope', () => {
  it('только openid → ни email, ни name', () => {
    expect(profileForScope(PROFILE, 'openid')).toEqual({});
  });

  it('email → email и email_verified, без name', () => {
    expect(profileForScope(PROFILE, 'openid email')).toEqual({
      email: 'user@x.com',
      emailVerified: true,
    });
  });

  it('profile → только name', () => {
    expect(profileForScope(PROFILE, 'openid profile')).toEqual({ name: 'Иван' });
  });

  it('profile + email → всё', () => {
    expect(profileForScope(PROFILE, 'openid profile email')).toEqual(PROFILE);
  });

  it('неизвестный scope не открывает ничего сверх известного', () => {
    expect(profileForScope(PROFILE, 'openid admin')).toEqual({});
  });
});
