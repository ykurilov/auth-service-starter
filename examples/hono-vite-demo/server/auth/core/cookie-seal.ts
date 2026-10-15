// Запечатывание cookie: AES-256-GCM. Ключ выводим из секрета через SHA-256
// (ровно 32 байта под AES-256). Конверт: "v2.<iv>.<ciphertext>"; срок жизни внутри шифротекста, сегменты
// base64url. GCM аутентифицирует шифротекст — подмена/порча падают при
// расшифровке, и мы возвращаем null (не бросаем).
const VERSION = 'v2';

function toB64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Возвращаем Uint8Array<ArrayBuffer> явно: в TS 5.9 Uint8Array стал generic по
// ArrayBufferLike, а crypto.subtle требует BufferSource с конкретным ArrayBuffer.
function fromB64url(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(secret: string): Promise<CryptoKey> {
  const material = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret));
  return crypto.subtle.importKey('raw', material, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

export async function seal(data: unknown, secret: string, ttlSeconds = 30 * 24 * 3600): Promise<string> {
  const key = await deriveKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify({ data, expiresAt: Date.now() + ttlSeconds * 1000 }));
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext),
  );
  return `${VERSION}.${toB64url(iv)}.${toB64url(cipher)}`;
}

export async function unseal<T = unknown>(sealed: string, secret: string): Promise<T | null> {
  try {
    const parts = sealed.split('.');
    if (parts.length !== 3) return null;
    const [version, ivPart, cipherPart] = parts as [string, string, string];
    if (version !== VERSION) return null;
    const key = await deriveKey(secret);
    const iv = fromB64url(ivPart);
    const cipher = fromB64url(cipherPart);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
    const envelope = JSON.parse(new TextDecoder().decode(plaintext));
    if (!envelope || !Number.isFinite(envelope.expiresAt) || envelope.expiresAt <= Date.now()) return null;
    return envelope.data as T;
  } catch {
    // Любая порча — неверный тег GCM, невалидный base64url, битый JSON — трактуем
    // как отсутствие валидной сессии.
    return null;
  }
}
