import { describe, it, expect } from 'vitest';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { TokenService } from '../../../src/domain/tokens/token-service.js';
import { loadSigningKey } from '../../../src/domain/tokens/signing-key.js';
import { fakeClock } from '../../helpers/fake-clock.js';

const config = {
  issuer: 'https://auth.example.com',
  accessTtlSeconds: 900,
  idTtlSeconds: 900,
};

async function makeService() {
  const key = await loadSigningKey({ autogenerate: true });
  const clock = fakeClock(new Date('2026-01-01T00:00:00.000Z'));
  return new TokenService(key, [key], clock, config);
}

const input = {
  userId: 'user-1',
  clientId: 'client-1',
  provider: 'google',
  roles: ['student'],
  profile: { email: 'u@example.com', emailVerified: true, name: 'U' },
  scope: 'openid profile email',
};

describe('TokenService.issueAccessAndId', () => {
  it('выпускает access-токен с ролями и корректными полями', async () => {
    const service = await makeService();
    const pair = await service.issueAccessAndId(input);

    const claims = decodeJwt(pair.accessToken);
    expect(claims.iss).toBe(config.issuer);
    expect(claims.sub).toBe('user-1');
    expect(claims.aud).toBe('client-1');
    expect(claims.roles).toEqual(['student']);
    expect(claims.iat).toBe(1767225600);
    expect(claims.exp).toBe(1767225600 + 900);
  });

  it('кладёт kid в заголовок токена', async () => {
    const service = await makeService();
    const pair = await service.issueAccessAndId(input);
    const header = decodeProtectedHeader(pair.accessToken);
    expect(header.alg).toBe('RS256');
    expect(header.kid).toBeTruthy();
  });

  it('выпускает id-токен с профилем и способом входа', async () => {
    const service = await makeService();
    const pair = await service.issueAccessAndId(input);
    const claims = decodeJwt(pair.idToken);
    expect(claims.email).toBe('u@example.com');
    expect(claims.email_verified).toBe(true);
    expect(claims.auth_provider).toBe('google');
  });

  it('возвращает expiresIn', async () => {
    const service = await makeService();
    const pair = await service.issueAccessAndId(input);
    expect(pair.expiresIn).toBe(900);
  });

  it('кладёт запрошенный scope в access-токен и в ответ', async () => {
    const service = await makeService();
    const pair = await service.issueAccessAndId({ ...input, scope: 'openid email' });
    expect(decodeJwt(pair.accessToken).scope).toBe('openid email');
    expect(pair.scope).toBe('openid email');
  });

  it('scope=openid → id-токен без email и name (нет утечки PII)', async () => {
    const service = await makeService();
    const pair = await service.issueAccessAndId({ ...input, scope: 'openid' });
    const claims = decodeJwt(pair.idToken);
    expect(claims.email).toBeUndefined();
    expect(claims.email_verified).toBeUndefined();
    expect(claims.name).toBeUndefined();
    // auth_provider и sub не привязаны к scope и остаются.
    expect(claims.auth_provider).toBe('google');
    expect(claims.sub).toBe('user-1');
  });

  it('scope=openid email → есть email, но нет name', async () => {
    const service = await makeService();
    const pair = await service.issueAccessAndId({ ...input, scope: 'openid email' });
    const claims = decodeJwt(pair.idToken);
    expect(claims.email).toBe('u@example.com');
    expect(claims.email_verified).toBe(true);
    expect(claims.name).toBeUndefined();
  });

  it('verifyAccessToken возвращает scope', async () => {
    const service = await makeService();
    const pair = await service.issueAccessAndId({ ...input, scope: 'openid profile' });
    const claims = await service.verifyAccessToken(pair.accessToken);
    expect(claims.scope).toBe('openid profile');
  });
});

describe('TokenService.verifyAccessToken', () => {
  it('принимает валидный токен и возвращает claims', async () => {
    const service = await makeService();
    const pair = await service.issueAccessAndId(input);
    const claims = await service.verifyAccessToken(pair.accessToken);
    expect(claims.sub).toBe('user-1');
    expect(claims.roles).toEqual(['student']);
  });

  it('отвергает токен, подписанный чужим ключом', async () => {
    const service = await makeService();
    const other = await makeService();
    const pair = await other.issueAccessAndId(input);
    await expect(service.verifyAccessToken(pair.accessToken)).rejects.toThrow();
  });

  it('отвергает истёкший токен', async () => {
    const key = await loadSigningKey({ autogenerate: true });
    const issueClock = fakeClock(new Date('2026-01-01T00:00:00.000Z'));
    const issueService = new TokenService(key, [key], issueClock, config);
    const pair = await issueService.issueAccessAndId(input);
    // exp = 00:15:00; проверяем «сейчас» = 01:00:00 того же дня → токен протух
    const laterClock = fakeClock(new Date('2026-01-01T01:00:00.000Z'));
    const verifyService = new TokenService(key, [key], laterClock, config);
    await expect(verifyService.verifyAccessToken(pair.accessToken)).rejects.toThrow();
  });

  it('верифицирует токен, если его ключ есть в verificationKeys (даже когда активный ключ другой)', async () => {
    // Ключ A выпустил токен, затем произошла ротация: активным стал B, но A
    // остался среди verificationKeys (retired). Токен, выпущенный A, должен
    // проверяться по kid, а не по активному ключу.
    const keyA = await loadSigningKey({ autogenerate: true });
    const keyB = await loadSigningKey({ autogenerate: true });
    const clock = fakeClock(new Date('2026-01-01T00:00:00.000Z'));
    const issuerWithA = new TokenService(keyA, [keyA], clock, config);
    const pair = await issuerWithA.issueAccessAndId(input);
    // Новый сервис: активный B, но verificationKeys содержат и A, и B.
    const verifier = new TokenService(keyB, [keyB, keyA], clock, config);
    const claims = await verifier.verifyAccessToken(pair.accessToken);
    expect(claims.sub).toBe('user-1');
  });

  it('отвергает id-токен, предъявленный как access-токен (защита от подмены типа)', async () => {
    // id_token подписан тем же ключом и issuer, но у него нет typ:at+jwt.
    // Без проверки typ его можно было бы предъявить на /userinfo как Bearer.
    const service = await makeService();
    const pair = await service.issueAccessAndId(input);
    await expect(service.verifyAccessToken(pair.idToken)).rejects.toThrow();
  });

  it('отвергает токен, чей kid отсутствует среди verificationKeys', async () => {
    const keyA = await loadSigningKey({ autogenerate: true });
    const keyB = await loadSigningKey({ autogenerate: true });
    const clock = fakeClock(new Date('2026-01-01T00:00:00.000Z'));
    const issuerWithA = new TokenService(keyA, [keyA], clock, config);
    const pair = await issuerWithA.issueAccessAndId(input);
    // verificationKeys не содержат kid ключа A → неизвестный kid.
    const verifier = new TokenService(keyB, [keyB], clock, config);
    await expect(verifier.verifyAccessToken(pair.accessToken)).rejects.toThrow();
  });
});
