import { describe, it, expect } from 'vitest';
import { decodeJwtClaims } from '../../../module/server/core/claims.js';

// base64url(JSON) без реальной подписи: третий сегмент не важен — подпись не проверяем.
// Отклонение от плана: прямой btoa(JSON.stringify(...)) падает на не-latin1
// символах (юникод в name) — btoa кодирует только code unit 0..255. Кодируем
// через TextEncoder -> байты -> btoa, тем же приёмом, что и в самой claims.ts.
function fakeJwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) => {
    const bytes = new TextEncoder().encode(JSON.stringify(o));
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  return `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64(payload)}.signature-игнорируется`;
}

describe('decodeJwtClaims', () => {
  it('декодирует payload id_token', () => {
    const jwt = fakeJwt({ sub: 'u1', email: 'a@b.co', email_verified: true, name: 'Аня' });
    expect(decodeJwtClaims(jwt)).toEqual({
      sub: 'u1',
      email: 'a@b.co',
      email_verified: true,
      name: 'Аня',
    });
  });

  it('декодирует roles из access_token', () => {
    const jwt = fakeJwt({ sub: 'u1', roles: ['admin', 'user'] });
    expect(decodeJwtClaims(jwt)?.roles).toEqual(['admin', 'user']);
  });

  it('корректно декодирует юникод в name', () => {
    const jwt = fakeJwt({ sub: 'u1', name: 'Юрий Курилов' });
    expect(decodeJwtClaims(jwt)?.name).toBe('Юрий Курилов');
  });

  it('битый токен -> null', () => {
    expect(decodeJwtClaims('не.jwt')).toBeNull();
    expect(decodeJwtClaims('a.b')).toBeNull();
    expect(decodeJwtClaims('a.@@@.c')).toBeNull();
    expect(decodeJwtClaims('')).toBeNull();
  });
});
