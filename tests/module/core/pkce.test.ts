import { describe, it, expect } from 'vitest';
import { createPkce, computeChallenge } from '../../../module/server/core/pkce.js';

describe('createPkce', () => {
  it('verifier и state — непустые base64url без padding', async () => {
    const { verifier, challenge, state } = await createPkce();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(state).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(challenge).not.toContain('=');
  });

  it('каждый вызов даёт разные verifier/state', async () => {
    const a = await createPkce();
    const b = await createPkce();
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.state).not.toBe(b.state);
  });

  it('challenge = base64url(sha256(verifier)) по S256', async () => {
    const { verifier, challenge } = await createPkce();
    expect(await computeChallenge(verifier)).toBe(challenge);
  });

  it('computeChallenge стабилен для известного вектора (RFC 7636)', async () => {
    // Вектор из RFC 7636 приложение B.
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(await computeChallenge(verifier)).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
  });
});
