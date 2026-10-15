import type { Clock } from '../../src/ports/clock.js';

export function fakeClock(fixed: Date): Clock {
  return { now: () => new Date(fixed.getTime()) };
}
