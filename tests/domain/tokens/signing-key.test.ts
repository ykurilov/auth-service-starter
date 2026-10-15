import { describe, it, expect } from 'vitest';
import { generateKeyPair, exportPKCS8, exportSPKI, SignJWT, jwtVerify } from 'jose';
import { loadSigningKey } from '../../../src/domain/tokens/signing-key.js';

describe('loadSigningKey', () => {
  it('автогенерирует ключ с kid и публичным JWK', async () => {
    const key = await loadSigningKey({ autogenerate: true });

    expect(key.kid).toBeTruthy();
    expect(key.publicJwk.kid).toBe(key.kid);
    expect(key.publicJwk.alg).toBe('RS256');
    expect(key.publicJwk.use).toBe('sig');
    expect(key.publicJwk.kty).toBe('RSA');
  });

  it('использует переданный kid', async () => {
    const key = await loadSigningKey({ autogenerate: true, kid: 'my-kid' });
    expect(key.kid).toBe('my-kid');
  });

  it('бросает ошибку без ключей и без autogenerate', async () => {
    await expect(loadSigningKey({ autogenerate: false })).rejects.toThrow();
  });

  it('загружает ключ из PEM (боевой путь) и им можно подписать/проверить', async () => {
    // готовим настоящую PEM-пару, как в проде
    const pair = await generateKeyPair('RS256', { extractable: true });
    const privateKeyPem = await exportPKCS8(pair.privateKey);
    const publicKeyPem = await exportSPKI(pair.publicKey);

    const key = await loadSigningKey({
      privateKeyPem,
      publicKeyPem,
      kid: 'pem-kid',
      autogenerate: false,
    });

    expect(key.kid).toBe('pem-kid');
    expect(key.publicJwk.kty).toBe('RSA');
    expect(key.publicJwk.kid).toBe('pem-kid');

    // подпись импортированным приватным ключом проверяется импортированным публичным
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256' })
      .sign(key.privateKey);
    const { payload } = await jwtVerify(jwt, key.publicKey);
    expect(payload).toBeTruthy();
  });
});
