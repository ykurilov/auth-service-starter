import { createHash } from 'node:crypto';

// SHA-256 в hex. Для высокоэнтропийных секретов (коды, refresh-токены):
// перебор невозможен, обратимость не нужна, важна лишь детерминированность.
export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
