import { getUser } from '@/auth';
import { headers } from 'next/headers';

export default async function Dashboard() {
  const user = await getUser((await headers()).get('cookie'));
  // Сюда без входа не попасть: middleware редиректит на login.
  return (
    <main>
      <h1>Личный кабинет</h1>
      <p>Защищённая страница. Данные пользователя из сессии:</p>
      <pre style={{ background: '#f4f4f4', padding: 12, borderRadius: 6 }}>
        {JSON.stringify(user, null, 2)}
      </pre>
      <p>
        <a href="/">На главную</a> · <a href="/api/auth/logout">Выйти</a>
      </p>
    </main>
  );
}
