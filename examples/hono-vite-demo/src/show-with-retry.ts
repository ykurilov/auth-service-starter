// Рисует страницу, а если сервис входа или API недоступны (сеть, 503) —
// вместо вечного «Проверяю вход…» показывает причину и кнопку «Повторить».
// Повтор не трогает cookie: временный сбой входа не сбрасывает.
export function showWithRetry(app: Element, render: (app: Element) => Promise<void>): void {
  app.textContent = 'Проверяю вход…';
  render(app).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : 'Не удалось загрузить страницу.';
    app.innerHTML = `<p role="alert"></p><p><button type="button">Повторить</button></p>`;
    app.querySelector('[role="alert"]')!.textContent = message;
    app.querySelector('button')!.addEventListener('click', () => showWithRetry(app, render));
  });
}
