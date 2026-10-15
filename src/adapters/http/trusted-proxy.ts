// Новые установки используют явный список IP/CIDR. Совместимость true/N
// ограничена loopback: одного количества хопов недостаточно для доверия адресу.
export function trustedProxy(setting: number | string[]): false | string[] | ((address: string, hop: number) => boolean) {
  if (Array.isArray(setting)) return setting;
  if (setting === 0) return false;
  return (address, hop) => hop < setting && (
    address === '::1' || address.startsWith('127.') || address.startsWith('::ffff:127.')
  );
}
