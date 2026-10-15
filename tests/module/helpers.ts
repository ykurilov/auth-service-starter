import { LOGOUT_COOKIE } from '../../module/server/cookies.js';

export async function confirmLogout(send: (req: Request) => Response | Promise<Response>, appUrl: string, cookie: string) {
  const page = await send(new Request(`${appUrl}/api/auth/logout`, { headers: { cookie } }));
  const token = (await page.text()).match(/name="csrf" value="([^"]+)"/)?.[1];
  if (!token) throw new Error('Нет подтверждения выхода');
  const csrfCookie = page.headers.getSetCookie().find((c) => c.startsWith(`${LOGOUT_COOKIE}=`) || c.startsWith('auth_logout='))!.split(';')[0]!;
  return send(new Request(`${appUrl}/api/auth/logout`, {
    method: 'POST', headers: { cookie: `${cookie}; ${csrfCookie}`, origin: appUrl },
    body: new URLSearchParams({ csrf: token }),
  }));
}
