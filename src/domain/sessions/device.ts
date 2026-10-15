import { sha256Hex } from '../shared/hash.js';

export interface DeviceInfo {
  userAgent?: string;
  ip?: string;
}

// Мягкая привязка: отпечаток по user-agent (без IP). Пустой UA -> стабильный маркер.
export function fingerprintDevice(device: DeviceInfo): string {
  return sha256Hex(`ua:${device.userAgent ?? 'unknown'}`);
}

// IP — только для аудита, храним хешем.
export function hashIp(ip: string | undefined): string {
  return sha256Hex(`ip:${ip ?? 'unknown'}`);
}
