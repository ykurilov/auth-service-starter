import { describe, it, expect } from 'vitest';
import { sha256Hex } from '../../../src/domain/shared/hash.js';

describe('sha256Hex', () => {
  it('даёт стабильный hex-хеш', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('разные входы -> разные хеши', () => {
    expect(sha256Hex('a')).not.toBe(sha256Hex('b'));
  });
});
