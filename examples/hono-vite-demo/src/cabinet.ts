import { requireUser, LOGOUT_URL } from './auth-client';

// Кабинет только для вошедших: без входа requireUser() уводит на вход и после
// него возвращает сюда. Заметки — защищённый API на сервере Hono.
async function render(app: Element) {
  const user = await requireUser();
  const res = await fetch('/api/notes');
  const { notes } = (await res.json()) as { notes: string[] };

  app.innerHTML = `
    <p>Данные пользователя из сессии:</p>
    <pre id="user" style="background:#f4f4f4;padding:12px;border-radius:6px"></pre>
    <p>Заметки с сервера: <span id="notes"></span></p>
    <p><a href="/">На главную</a> · <a href="${LOGOUT_URL}">Выйти</a></p>`;
  app.querySelector('#user')!.textContent = JSON.stringify(user, null, 2);
  app.querySelector('#notes')!.textContent = notes.join(', ');
}

void render(document.querySelector('#app')!);
