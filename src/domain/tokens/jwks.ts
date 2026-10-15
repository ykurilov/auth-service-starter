import type { JWK } from 'jose';
import type { SigningKey } from './signing-key.js';

export interface Jwks {
  keys: JWK[];
}

export function toJwks(keys: SigningKey[]): Jwks {
  return { keys: keys.map((k) => k.publicJwk) };
}
