// Декодирование payload JWT БЕЗ проверки подписи. Токены приходят напрямую от
// сервиса по TLS (server-to-server), а cookie аутентифицирована AES-GCM — второй
// раз проверять RS256 незачем, и это убирает зависимость от jose.
export interface JwtClaims {
  sub?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  roles?: string[];
  auth_provider?: string;
  exp?: number;
  [key: string]: unknown;
}

// Uint8Array<ArrayBuffer> явно: в TS 5.9 Uint8Array generic по ArrayBufferLike,
// а TextDecoder.decode ожидает BufferSource с конкретным ArrayBuffer.
function fromB64url(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function decodeJwtClaims(jwt: string): JwtClaims | null {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;
    const [, payloadPart] = parts as [string, string, string];
    const json = new TextDecoder().decode(fromB64url(payloadPart));
    const parsed = JSON.parse(json);
    if (typeof parsed !== 'object' || parsed === null) return null;
    return parsed as JwtClaims;
  } catch {
    return null;
  }
}
