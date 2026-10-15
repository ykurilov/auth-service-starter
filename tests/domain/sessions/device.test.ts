import { describe, it, expect } from 'vitest';
import { fingerprintDevice, hashIp, type DeviceInfo } from '../../../src/domain/sessions/device.js';

describe('device', () => {
  it('одинаковый user-agent -> одинаковый отпечаток', () => {
    const d: DeviceInfo = { userAgent: 'Mozilla/5.0', ip: '1.2.3.4' };
    expect(fingerprintDevice(d)).toBe(fingerprintDevice({ ...d, ip: '9.9.9.9' }));
  });

  it('разный user-agent -> разный отпечаток', () => {
    expect(fingerprintDevice({ userAgent: 'A' })).not.toBe(fingerprintDevice({ userAgent: 'B' }));
  });

  it('пустой user-agent даёт стабильный отпечаток "unknown"', () => {
    expect(fingerprintDevice({})).toBe(fingerprintDevice({ ip: '1.1.1.1' }));
  });

  it('hashIp детерминирован и не хранит сырой ip', () => {
    expect(hashIp('1.2.3.4')).toBe(hashIp('1.2.3.4'));
    expect(hashIp('1.2.3.4')).not.toContain('1.2.3.4');
    expect(hashIp(undefined)).toBe(hashIp(undefined));
  });
});
