import {
  importPKCS8,
  importSPKI,
  generateKeyPair,
  exportJWK,
  exportPKCS8,
  exportSPKI,
  calculateJwkThumbprint,
  type KeyLike,
  type JWK,
} from 'jose';

export interface SigningKey {
  kid: string;
  privateKey: KeyLike;
  publicKey: KeyLike;
  publicJwk: JWK;
}

// Сгенерированная пара в переносимом PEM-формате — то, что кладётся в стор.
export interface GeneratedKeyPem {
  kid: string;
  privatePem: string;
  publicPem: string;
  alg: string;
}

// Генерирует новую RS256-пару и отдаёт её как PKCS8/SPKI PEM с kid-thumbprint.
export async function generateSigningKeyPem(): Promise<GeneratedKeyPem> {
  const { privateKey, publicKey } = await generateKeyPair('RS256', {
    extractable: true,
  });
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  const privatePem = await exportPKCS8(privateKey);
  const publicPem = await exportSPKI(publicKey);
  return { kid, privatePem, publicPem, alg: 'RS256' };
}

// Восстанавливает SigningKey из PEM-пары. Единая точка импорта для боевого
// PEM-пути и для ключей, поднятых из стора.
export async function signingKeyFromPem(
  privatePem: string,
  publicPem: string,
  kid?: string,
): Promise<SigningKey> {
  const privateKey = await importPKCS8(privatePem, 'RS256');
  const publicKey = await importSPKI(publicPem, 'RS256');
  const publicJwk = await exportJWK(publicKey);
  const finalKid = kid ?? (await calculateJwkThumbprint(publicJwk));
  publicJwk.kid = finalKid;
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';
  return { kid: finalKid, privateKey, publicKey, publicJwk };
}

export interface SigningKeyInput {
  privateKeyPem?: string;
  publicKeyPem?: string;
  kid?: string;
  autogenerate: boolean;
}

export async function loadSigningKey(input: SigningKeyInput): Promise<SigningKey> {
  if (input.privateKeyPem && input.publicKeyPem) {
    return signingKeyFromPem(input.privateKeyPem, input.publicKeyPem, input.kid);
  }
  if (input.autogenerate) {
    const gen = await generateSigningKeyPem();
    return signingKeyFromPem(gen.privatePem, gen.publicPem, input.kid ?? gen.kid);
  }
  throw new Error('signing key not provided and autogenerate disabled');
}
