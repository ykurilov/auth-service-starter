import { authCookieNames } from '../../module/server/cookies.js';
import { loadModuleConfig } from '../../module/server/core/config.js';

// Итоговые имена cookie приложения: префикс __Host- на HTTPS и суффикс client_id.
export function cookieNamesFor(env: Record<string, string | undefined>) {
  const config = loadModuleConfig({ env });
  return authCookieNames(config.clientId, config.appUrl);
}

export async function confirmLogout(send: (req: Request) => Response | Promise<Response>, appUrl: string, cookie: string) {
  const page = await send(new Request(`${appUrl}/api/auth/logout`, { headers: { cookie } }));
  const token = (await page.text()).match(/name="csrf" value="([^"]+)"/)?.[1];
  if (!token) throw new Error('Нет подтверждения выхода');
  const csrfCookie = page.headers.getSetCookie().find((c) => /^(__Host-)?auth_logout\./.test(c))!.split(';')[0]!;
  return send(new Request(`${appUrl}/api/auth/logout`, {
    method: 'POST', headers: { cookie: `${cookie}; ${csrfCookie}`, origin: appUrl },
    body: new URLSearchParams({ csrf: token }),
  }));
}
