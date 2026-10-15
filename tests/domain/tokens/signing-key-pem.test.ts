import { describe, it, expect } from 'vitest';
import {
  generateSigningKeyPem,
  signingKeyFromPem,
} from '../../../src/domain/tokens/signing-key.js';

describe('generateSigningKeyPem', () => {
  it('отдаёт валидные PKCS8/SPKI PEM, непустой kid и alg RS256', async () => {
    const gen = await generateSigningKeyPem();

    // Проверяется заголовок только что сгенерированного ключа, самого ключа в исходнике нет.
    expect(gen.privatePem.startsWith('-----BEGIN PRIVATE KEY-----')).toBe(true); // gitleaks:allow
    expect(gen.publicPem.startsWith('-----BEGIN PUBLIC KEY-----')).toBe(true);
    expect(gen.kid).toBeTruthy();
    expect(gen.alg).toBe('RS256');
  });
});

describe('signingKeyFromPem', () => {
  it('восстанавливает SigningKey с тем же kid и publicJwk.kid', async () => {
    const gen = await generateSigningKeyPem();
    const key = await signingKeyFromPem(gen.privatePem, gen.publicPem, gen.kid);

    expect(key.kid).toBe(gen.kid);
    expect(key.publicJwk.kid).toBe(gen.kid);
    expect(key.publicJwk.alg).toBe('RS256');
    expect(key.publicJwk.use).toBe('sig');
    expect(key.publicJwk.kty).toBe('RSA');
  });

  it('без kid вычисляет thumbprint, совпадающий с generateSigningKeyPem', async () => {
    const gen = await generateSigningKeyPem();
    const key = await signingKeyFromPem(gen.privatePem, gen.publicPem);

    expect(key.kid).toBe(gen.kid);
  });
});
