import { ZodError } from 'zod';
import { InvalidClientError, InvalidGrantError } from '../../domain/login/errors.js';
import { InvalidRefreshTokenError } from '../../domain/sessions/errors.js';

export interface OAuthErrorResult {
  status: number;
  error: string;
}

// null = ошибка не из доменного набора OAuth (инфраструктурный сбой):
// вызывающий обязан пробросить её в глобальный errorHandler (500 + лог),
// а не маскировать под 400 — иначе клиентские библиотеки сочтут код/токен
// недействительным и не повторят запрос.
export function oauthErrorFor(err: unknown): OAuthErrorResult | null {
  if (err instanceof InvalidGrantError || err instanceof InvalidRefreshTokenError) {
    return { status: 400, error: 'invalid_grant' };
  }
  if (err instanceof InvalidClientError) {
    return { status: 401, error: 'invalid_client' };
  }
  if (err instanceof ZodError) {
    return { status: 400, error: 'invalid_request' };
  }
  return null;
}
