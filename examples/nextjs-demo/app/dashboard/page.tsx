import { Suspense } from 'react';
import { getUser } from '@/auth';
import { headers } from 'next/headers';

export default function Dashboard() {
  // Сюда без входа не попасть: proxy.ts редиректит на login.
  return (
    <main>
      <h1>Личный кабинет</h1>
      <p>Защищённая страница. Данные пользователя из сессии:</p>
      <Suspense fallback={<p>Загружаем профиль…</p>}>
        <Profile />
      </Suspense>
      <p>
        <a href="/">На главную</a> · <a href="/api/auth/logout">Выйти</a>
      </p>
    </main>
  );
}

async function Profile() {
  const user = await getUser((await headers()).get('cookie'));
  return (
    <pre style={{ background: '#f4f4f4', padding: 12, borderRadius: 6 }}>
      {JSON.stringify(user, null, 2)}
    </pre>
  );
}
