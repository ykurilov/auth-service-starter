import { getUser, silentCheckDone } from '@/auth';
import { headers } from 'next/headers';
import { redirect } from 'next/navigation';

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default async function Home({ searchParams }: Props) {
  const cookie = (await headers()).get('cookie');
  const user = await getUser(cookie);
  // Вошедший в единый SSO не должен видеть «Войти»: один раз тихо проверяем
  // SSO-сессию. Метка (в cookie или в адресе) не даёт уйти в круг редиректов.
  if (!user && !silentCheckDone(cookie, await searchParams))
    redirect('/api/auth/login?silent=1&next=/');
  return (
    <main>
      <h1>Демо-приложение auth-v3</h1>
      {user ? (
        <>
          <p>
            Вы вошли как <strong>{user.name ?? user.email ?? user.id}</strong>
            {user.email ? ` (${user.email})` : ''}.
          </p>
          <p>
            <a href="/dashboard">Личный кабинет</a> · <a href="/api/auth/logout">Выйти</a>
          </p>
        </>
      ) : (
        <>
          <p>Вы не авторизованы. Главная страница доступна всем.</p>
          <p>
            <a href="/api/auth/login?next=/dashboard">Войти</a> ·{' '}
            <a href="/dashboard">Личный кабинет (потребует входа)</a>
          </p>
        </>
      )}
    </main>
  );
}
