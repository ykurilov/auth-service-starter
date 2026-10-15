import { describe, it, expect } from 'vitest';
import { trustedProxy } from '../../../src/adapters/http/trusted-proxy.js';

describe('trusted proxy boundary', () => {
  it('старый hop-count не доверяет публичному origin, доступному в обход nginx', () => {
    const trust = trustedProxy(1);
    if (typeof trust !== 'function') throw new Error('expected predicate');
    expect(trust('203.0.113.1', 0)).toBe(false);
    expect(trust('127.0.0.1', 0)).toBe(true);
    expect(trust('::1', 0)).toBe(true);
    expect(trust('::ffff:127.0.0.1', 0)).toBe(true);
    expect(trust('127.0.0.1', 1)).toBe(false);
  });
  it('явные IP/CIDR сохраняют границу сети, 0 отключает proxy headers', () => {
    expect(trustedProxy(0)).toBe(false);
    expect(trustedProxy(['loopback', '172.30.240.1'])).toEqual(['loopback', '172.30.240.1']);
  });
});
