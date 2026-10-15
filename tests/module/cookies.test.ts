import { describe, it, expect } from 'vitest';
import {
  serializeCookie,
  parseCookies,
  SESSION_COOKIE,
  FLOW_COOKIE,
} from '../../module/server/cookies.js';

describe('serializeCookie', () => {
  it('базовые атрибуты: HttpOnly, SameSite=Lax, Path=/', () => {
    const c = serializeCookie(SESSION_COOKIE, 'val', { maxAgeSeconds: 100, secure: true });
    expect(c).toContain('auth_session=val');
    expect(c).toContain('HttpOnly');
    expect(c).toContain('SameSite=Lax');
    expect(c).toContain('Path=/');
    expect(c).toContain('Max-Age=100');
    expect(c).toContain('Secure');
  });

  it('secure:false опускает Secure (для http://localhost)', () => {
    const c = serializeCookie(SESSION_COOKIE, 'val', { maxAgeSeconds: 100, secure: false });
    expect(c).not.toContain('Secure');
  });

  it('удаление cookie: Max-Age=0 и пустое значение', () => {
    const c = serializeCookie(SESSION_COOKIE, '', { maxAgeSeconds: 0, secure: true });
    expect(c).toContain('auth_session=;');
    expect(c).toContain('Max-Age=0');
  });
});

describe('parseCookies', () => {
  it('разбирает несколько cookie из заголовка', () => {
    const map = parseCookies(`${SESSION_COOKIE}=abc; ${FLOW_COOKIE}=xyz; other=1`);
    expect(map[SESSION_COOKIE]).toBe('abc');
    expect(map[FLOW_COOKIE]).toBe('xyz');
  });
  it('пустой/отсутствующий заголовок -> пустая карта', () => {
    expect(parseCookies(null)).toEqual({});
    expect(parseCookies('')).toEqual({});
  });
});
