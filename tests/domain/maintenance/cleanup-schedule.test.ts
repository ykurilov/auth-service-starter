import { describe, it, expect, vi, afterEach } from 'vitest';
import { startCleanupSchedule } from '../../../src/domain/maintenance/cleanup-schedule.js';

afterEach(() => { vi.useRealTimers(); });

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

describe('T29: расписание фоновой очистки', () => {
  it('первый прогон сразу, следующий — через интервал после конца предыдущего', async () => {
    vi.useFakeTimers();
    const run = vi.fn(async () => {});
    const schedule = startCleanupSchedule(run, 1000);
    await vi.advanceTimersByTimeAsync(0);
    expect(run).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1000);
    expect(run).toHaveBeenCalledTimes(2);
    await schedule.stop();
  });

  it('stop дожидается текущего прогона', async () => {
    const gate = deferred();
    const events: string[] = [];
    const schedule = startCleanupSchedule(async () => { await gate.promise; events.push('прогон закончен'); }, 1000);
    const stopping = schedule.stop().then(() => events.push('остановлено'));
    await Promise.resolve();
    expect(events).toEqual([]);
    gate.resolve();
    await stopping;
    expect(events).toEqual(['прогон закончен', 'остановлено']);
  });

  it('после stop новых прогонов нет: таймер снят, даже если прогон шёл во время stop', async () => {
    vi.useFakeTimers();
    const gate = deferred();
    let calls = 0;
    const schedule = startCleanupSchedule(async () => { calls++; if (calls === 1) await gate.promise; }, 1000);
    await vi.advanceTimersByTimeAsync(0);
    const stopping = schedule.stop();
    gate.resolve();
    await stopping;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(calls).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('сбой прогона не останавливает расписание', async () => {
    vi.useFakeTimers();
    let calls = 0;
    const schedule = startCleanupSchedule(async () => { calls++; throw new Error('db down'); }, 1000, () => {});
    await vi.advanceTimersByTimeAsync(1000);
    expect(calls).toBe(2);
    await schedule.stop();
  });
});
