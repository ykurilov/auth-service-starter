// PKCE (RFC 7636) и state на Web Crypto — без node:*.
// base64url без padding: формат code_challenge и удобные непрозрачные строки.
function base64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomBase64url(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

// verifier: 32 случайных байта -> 43 символа base64url (в допустимом диапазоне 43..128).
export async function computeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

export interface Pkce {
  verifier: string;
  challenge: string;
  state: string;
}

export async function createPkce(): Promise<Pkce> {
  const verifier = randomBase64url(32);
  const challenge = await computeChallenge(verifier);
  const state = randomBase64url(16);
  return { verifier, challenge, state };
}
