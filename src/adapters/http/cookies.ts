import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../../config/config.js';
import { BROWSER_BINDING_TTL_SECONDS } from '../../domain/sso/sso-session.js';

// Имя cookie сервиса. На HTTPS — с префиксом __Host-: браузер принимает такую
// cookie только с Secure, Path=/ и без Domain, поэтому соседний поддомен не
// может подбросить (cookie tossing) свою sso/csrf. Старые имена без префикса на
// HTTPS не читаются вовсе — иначе подброшенная legacy-cookie снова сработала бы.
// Локальная разработка по http (Secure выключен) — обычные имена.
export function hostCookieName(config: Config, base: string): string {
  if (!config.ssoCookieSecure || base.startsWith('__Host-')) return base;
  return `__Host-${base}`;
}

export function ssoCookieName(config: Config): string {
  return hostCookieName(config, config.ssoCookieName);
}

export function setSsoCookie(reply: FastifyReply, config: Config, rawToken: string): void {
  reply.setCookie(ssoCookieName(config), rawToken, {
    httpOnly: true,
    secure: config.ssoCookieSecure,
    sameSite: 'lax',
    path: '/',
    maxAge: config.ssoTtlSeconds,
  });
}

export function clearSsoCookie(reply: FastifyReply, config: Config): void {
  // Атрибуты должны совпадать с setSsoCookie, иначе часть браузеров/прокси
  // не сопоставит удаляющую cookie с установленной и не сотрёт её.
  reply.clearCookie(ssoCookieName(config), {
    httpOnly: true,
    secure: config.ssoCookieSecure,
    sameSite: 'lax',
    path: '/',
  });
}

export function readSsoCookie(req: FastifyRequest, config: Config): string | null {
  const v = req.cookies[ssoCookieName(config)];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

// Cookie привязки браузера к цепочке SSO (см. BrowserBinding): входа не даёт,
// живёт дольше сессий приложений. Атрибуты — как у SSO-cookie.
export function bindingCookieName(config: Config): string {
  return hostCookieName(config, `${config.ssoCookieName}_browser`);
}

export function setBindingCookie(reply: FastifyReply, config: Config, rawToken: string): void {
  reply.setCookie(bindingCookieName(config), rawToken, {
    httpOnly: true,
    secure: config.ssoCookieSecure,
    sameSite: 'lax',
    path: '/',
    maxAge: BROWSER_BINDING_TTL_SECONDS,
  });
}

export function clearBindingCookie(reply: FastifyReply, config: Config): void {
  reply.clearCookie(bindingCookieName(config), {
    httpOnly: true,
    secure: config.ssoCookieSecure,
    sameSite: 'lax',
    path: '/',
  });
}

export function readBindingCookie(req: FastifyRequest, config: Config): string | null {
  const v = req.cookies[bindingCookieName(config)];
  return typeof v === 'string' && v.length > 0 ? v : null;
}
