import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../../config/config.js';
import { hostCookieName } from './cookies.js';

// CSRF форм входа и выхода — три слоя:
//  1. double-submit: значение csrf-cookie дублируется скрытым полем формы;
//  2. __Host- имя cookie на HTTPS: соседний поддомен не подбросит своё значение;
//  3. проверка Origin/Sec-Fetch-Site: POST с чужого origin (в т.ч. соседнего
//     поддомена того же сайта, где SameSite=Lax не помогает) отклоняется.
// Значение cookie заодно служит привязкой к браузеру для попыток входа по коду
// и nonce Google, поэтому оно не ротируется при открытии другой формы.

export function csrfCookieName(config: Config): string {
  return hostCookieName(config, config.csrfCookieName);
}

export function readCsrfCookie(req: FastifyRequest, config: Config): string | null {
  const v = req.cookies[csrfCookieName(config)];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

export function issueCsrf(reply: FastifyReply, config: Config): string {
  const token = randomBytes(32).toString('base64url');
  reply.setCookie(csrfCookieName(config), token, {
    httpOnly: true,
    secure: config.ssoCookieSecure,
    sameSite: 'lax',
    path: '/',
  });
  return token;
}

// Действующий токен браузера; новый — только если cookie ещё нет. Открытие
// второй формы (другая вкладка, экран согласия, выход) не ломает первую.
export function ensureCsrf(req: FastifyRequest, reply: FastifyReply, config: Config): string {
  return readCsrfCookie(req, config) ?? issueCsrf(reply, config);
}

export function verifyCsrf(req: FastifyRequest, config: Config, fieldValue: unknown): boolean {
  const cookie = readCsrfCookie(req, config);
  if (cookie === null || typeof fieldValue !== 'string') return false;
  const a = Buffer.from(cookie);
  const b = Buffer.from(fieldValue);
  return a.length === b.length && timingSafeEqual(a, b);
}

// POST пришёл со страницы самого сервиса. Origin есть у форм всех современных
// браузеров — он обязан совпасть с origin issuer. Без Origin смотрим
// Sec-Fetch-Site. Клиенты без обоих заголовков (старые браузеры, curl) остаются
// под защитой double-submit и __Host-.
export function isSameOriginRequest(req: FastifyRequest, config: Config): boolean {
  const expected = new URL(config.issuerUrl).origin;
  const origin = req.headers.origin;
  if (typeof origin === 'string') return origin === expected;
  const site = req.headers['sec-fetch-site'];
  if (typeof site === 'string') return site === 'same-origin' || site === 'none';
  return true;
}
