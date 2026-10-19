export interface CleanupSchedule {
  // Снимает следующий запуск и дожидается текущего прогона, если он идёт.
  stop(): Promise<void>;
}

// Фоновая очистка: первый прогон сразу (не ждать интервал после старта),
// следующий — через intervalMs после конца предыдущего. Самоперепланирование
// вместо setInterval: прогоны не накладываются даже при медленной БД. unref:
// таймер не держит процесс живым. Сбой прогона уходит в onError и не
// останавливает расписание.
export function startCleanupSchedule(
  run: () => Promise<void>,
  intervalMs: number,
  onError: (err: unknown) => void = () => {},
): CleanupSchedule {
  let stopped = false;
  let timer: NodeJS.Timeout | undefined;
  let inFlight: Promise<void> = Promise.resolve();

  const tick = (): void => {
    timer = undefined;
    inFlight = run()
      .catch(onError)
      .finally(() => {
        if (!stopped) timer = setTimeout(tick, intervalMs).unref();
      });
  };
  tick();

  return {
    async stop() {
      stopped = true;
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
      await inFlight;
    },
  };
}
