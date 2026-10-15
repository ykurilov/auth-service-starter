import { describe, it, expect } from 'vitest';
import { systemClock } from '../../src/ports/clock.js';
import { fakeClock } from '../helpers/fake-clock.js';

describe('Clock', () => {
  it('systemClock возвращает текущее время', () => {
    const before = Date.now();
    const now = systemClock.now().getTime();
    expect(now).toBeGreaterThanOrEqual(before);
  });

  it('fakeClock возвращает фиксированный момент', () => {
    const fixed = new Date('2026-01-01T00:00:00.000Z');
    const clock = fakeClock(fixed);
    expect(clock.now().toISOString()).toBe('2026-01-01T00:00:00.000Z');
  });
});
