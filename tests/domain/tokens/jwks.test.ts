import { describe, it, expect } from 'vitest';
import { toJwks } from '../../../src/domain/tokens/jwks.js';
import { loadSigningKey } from '../../../src/domain/tokens/signing-key.js';

describe('toJwks', () => {
  it('возвращает набор ключей с публичным JWK', async () => {
    const key = await loadSigningKey({ autogenerate: true, kid: 'k1' });
    const jwks = toJwks([key]);

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]?.kid).toBe('k1');
    expect(jwks.keys[0]?.kty).toBe('RSA');
    // приватная часть не должна утечь
    expect(jwks.keys[0]?.d).toBeUndefined();
  });
});
