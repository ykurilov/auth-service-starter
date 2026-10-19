import { authCookieNames } from '../../module/server/cookies.js';
import { loadModuleConfig } from '../../module/server/core/config.js';
import { unseal } from '../../module/server/core/cookie-seal.js';

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

// next попытки входа: он едет запечатанным в state адреса /authorize.
export async function nextOfState(state: string | null, secret: string): Promise<string | undefined> {
  const idx = state?.indexOf('~') ?? -1;
  if (!state || idx === -1) return undefined;
  return (await unseal<{ next: string }>(state.slice(idx + 1), secret))?.next;
}
