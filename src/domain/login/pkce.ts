import { createHash, timingSafeEqual } from 'node:crypto';

// RFC 7636: challenge = BASE64URL(SHA256(ASCII(verifier))).
export function computeS256Challenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

// Сравнение устойчиво к timing-атаке. Разная длина -> сразу false.
export function verifyPkceS256(verifier: string, challenge: string): boolean {
  const a = Buffer.from(computeS256Challenge(verifier));
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
}
