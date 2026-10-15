import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { computeS256Challenge, verifyPkceS256 } from '../../../src/domain/login/pkce.js';

describe('PKCE S256', () => {
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

  it('computeS256Challenge = base64url(sha256(verifier))', () => {
    const expected = createHash('sha256').update(verifier).digest('base64url');
    expect(computeS256Challenge(verifier)).toBe(expected);
  });

  it('verifyPkceS256 принимает верный verifier', () => {
    const challenge = computeS256Challenge(verifier);
    expect(verifyPkceS256(verifier, challenge)).toBe(true);
  });

  it('verifyPkceS256 отклоняет неверный verifier', () => {
    const challenge = computeS256Challenge(verifier);
    expect(verifyPkceS256('другой-verifier', challenge)).toBe(false);
  });

  it('verifyPkceS256 отклоняет пустой/мусорный challenge', () => {
    expect(verifyPkceS256(verifier, '')).toBe(false);
    expect(verifyPkceS256(verifier, 'мусор')).toBe(false);
  });
});
