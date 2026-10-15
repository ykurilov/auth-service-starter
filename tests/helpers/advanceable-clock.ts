import type { Clock } from '../../src/ports/clock.js';

export interface AdvanceableClock extends Clock {
  advance(seconds: number): void;
  set(date: Date): void;
}

export function advanceableClock(start: Date): AdvanceableClock {
  let current = new Date(start.getTime());
  return {
    now: () => new Date(current.getTime()),
    advance: (seconds: number) => {
      current = new Date(current.getTime() + seconds * 1000);
    },
    set: (date: Date) => {
      current = new Date(date.getTime());
    },
  };
}
